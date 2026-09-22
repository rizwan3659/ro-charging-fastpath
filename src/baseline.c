/* SPDX-License-Identifier: MIT */
/* Baseline engine. Deliberately written the way first-version charging code
 * often looks: every AVP is copied into its own heap node, sessions and
 * accounts live in linked lists found by strcmp, and the answer is built
 * AVP by AVP into temporary buffers before being serialised. It is correct;
 * it is just slow as the number of active sessions grows. */
#include "diam.h"
#include "engine.h"

#include <stdlib.h>
#include <string.h>

struct node_avp {
	uint32_t code;
	uint8_t *data;
	size_t len;
	struct node_avp *next;
};

struct account {
	char msisdn[MSISDN_MAX + 1];
	uint32_t balance;
	struct account *next;
};

struct session {
	char id[SESSION_ID_MAX + 1];
	struct account *acct;
	uint32_t reserved;
	struct session *next;
};

struct engine {
	struct account *accounts;
	struct session *sessions;
	size_t nsessions, max_sessions;
};

static void free_avps(struct node_avp *a)
{
	while (a) {
		struct node_avp *n = a->next;
		free(a->data);
		free(a);
		a = n;
	}
}

/* Copies every AVP of [p, end) into a list. Returns NULL on error or if
 * empty; *err is set on error. */
static struct node_avp *parse_avps(const uint8_t *p, const uint8_t *end, int *err)
{
	struct node_avp *head = NULL, **tail = &head;
	struct avp a;
	int r;

	while ((r = diam_avp_next(&p, end, &a)) == 1) {
		struct node_avp *n = malloc(sizeof(*n));
		uint8_t *d = malloc(a.len ? a.len : 1);
		if (!n || !d) {
			free(n);
			free(d);
			*err = 1;
			break;
		}
		memcpy(d, a.data, a.len);
		n->code = a.code;
		n->data = d;
		n->len = a.len;
		n->next = NULL;
		*tail = n;
		tail = &n->next;
	}
	if (r < 0)
		*err = 1;
	return head;
}

static struct node_avp *find(struct node_avp *l, uint32_t code)
{
	for (; l; l = l->next)
		if (l->code == code)
			return l;
	return NULL;
}

static int get_u32(struct node_avp *l, uint32_t code, uint32_t *v)
{
	struct node_avp *a = find(l, code);
	if (!a || a->len != 4)
		return 0;
	*v = rd32(a->data);
	return 1;
}

/* Unit AVPs are grouped: parse again to reach CC-Time. */
static int get_unit(struct node_avp *l, uint32_t code, uint32_t *v)
{
	struct node_avp *g = find(l, code);
	int err = 0;
	if (!g)
		return 0;
	struct node_avp *in = parse_avps(g->data, g->data + g->len, &err);
	int ok = !err && get_u32(in, AVP_CC_TIME, v);
	free_avps(in);
	return ok;
}

static int get_msisdn(struct node_avp *l, char *out)
{
	struct node_avp *g = find(l, AVP_SUBSCRIPTION_ID);
	int err = 0, ok = 0;
	if (!g)
		return 0;
	struct node_avp *in = parse_avps(g->data, g->data + g->len, &err);
	struct node_avp *d = err ? NULL : find(in, AVP_SUBSCRIPTION_ID_DATA);
	if (d && d->len <= MSISDN_MAX) {
		memcpy(out, d->data, d->len);
		out[d->len] = 0;
		ok = 1;
	}
	free_avps(in);
	return ok;
}

static struct account *find_account(struct engine *e, const char *msisdn)
{
	for (struct account *a = e->accounts; a; a = a->next)
		if (strcmp(a->msisdn, msisdn) == 0)
			return a;
	return NULL;
}

static struct session **find_session(struct engine *e, const char *id)
{
	for (struct session **s = &e->sessions; *s; s = &(*s)->next)
		if (strcmp((*s)->id, id) == 0)
			return s;
	return NULL;
}

/* Answer assembly: each AVP is built into its own heap buffer first. */
static void add_out(struct node_avp ***tail, uint32_t code, const void *d, size_t len)
{
	struct node_avp *n = malloc(sizeof(*n));
	uint8_t *buf = malloc(pad4(DIAM_AVP_HDR + len));
	if (!n || !buf) {
		free(n);
		free(buf);
		return;
	}
	n->len = diam_put_avp(buf, code, d, len);
	n->code = code;
	n->data = buf;
	n->next = NULL;
	**tail = n;
	*tail = &n->next;
}

static void add_out_u32(struct node_avp ***tail, uint32_t code, uint32_t v)
{
	uint8_t b[4];
	wr32(b, v);
	add_out(tail, code, b, 4);
}

static size_t serialise(const uint8_t *req, struct node_avp *avps, uint8_t *out,
			size_t cap)
{
	size_t n = diam_put_hdr(out, 0, rd32(req + 12), rd32(req + 16));
	for (struct node_avp *a = avps; a; a = a->next) {
		if (n + a->len > cap)
			return 0;
		memcpy(out + n, a->data, a->len);
		n += a->len;
	}
	diam_finish(out, n);
	return n;
}

static size_t handle(struct engine *e, const uint8_t *ccr, size_t len,
		     uint8_t *out, size_t cap)
{
	size_t mlen = diam_check_ccr(ccr, len);
	if (!mlen)
		return 0;

	int err = 0;
	struct node_avp *req = parse_avps(ccr + DIAM_HDR_LEN, ccr + mlen, &err);
	struct node_avp *sid = find(req, AVP_SESSION_ID);
	uint32_t type = 0, num = 0, rc = DIAMETER_SUCCESS, grant = 0;
	int give_grant = 0;
	char id[SESSION_ID_MAX + 1] = "";

	if (sid && sid->len <= SESSION_ID_MAX) {
		memcpy(id, sid->data, sid->len);
		id[sid->len] = 0;
	}
	get_u32(req, AVP_CC_REQUEST_NUMBER, &num);

	if (err || !sid || sid->len > SESSION_ID_MAX ||
	    !get_u32(req, AVP_CC_REQUEST_TYPE, &type)) {
		rc = DIAMETER_UNABLE_TO_COMPLY;
	} else if (type == CC_INITIAL) {
		char msisdn[MSISDN_MAX + 1];
		uint32_t want = 0;
		struct account *a = get_msisdn(req, msisdn) ? find_account(e, msisdn) : NULL;
		get_unit(req, AVP_REQUESTED_SERVICE_UNIT, &want);
		if (!a)
			rc = DIAMETER_USER_UNKNOWN;
		else if (find_session(e, id) || e->nsessions >= e->max_sessions)
			rc = DIAMETER_UNABLE_TO_COMPLY;
		else if (a->balance == 0)
			rc = DIAMETER_CREDIT_LIMIT_REACHED;
		else {
			struct session *s = calloc(1, sizeof(*s));
			if (!s) {
				rc = DIAMETER_UNABLE_TO_COMPLY;
			} else {
				grant = want < a->balance ? want : a->balance;
				a->balance -= grant;
				strcpy(s->id, id);
				s->acct = a;
				s->reserved = grant;
				s->next = e->sessions;
				e->sessions = s;
				e->nsessions++;
				give_grant = 1;
			}
		}
	} else if (type == CC_UPDATE || type == CC_TERMINATION) {
		struct session **sp = find_session(e, id);
		if (!sp) {
			rc = DIAMETER_UNKNOWN_SESSION_ID;
		} else {
			struct session *s = *sp;
			uint32_t used = 0, want = 0;
			get_unit(req, AVP_USED_SERVICE_UNIT, &used);
			if (used > s->reserved)
				used = s->reserved;
			s->acct->balance += s->reserved - used;
			s->reserved = 0;
			if (type == CC_TERMINATION) {
				*sp = s->next;
				free(s);
				e->nsessions--;
			} else {
				get_unit(req, AVP_REQUESTED_SERVICE_UNIT, &want);
				grant = want < s->acct->balance ? want : s->acct->balance;
				if (grant == 0) {
					rc = DIAMETER_CREDIT_LIMIT_REACHED;
				} else {
					s->acct->balance -= grant;
					s->reserved = grant;
					give_grant = 1;
				}
			}
		}
	} else {
		rc = DIAMETER_UNABLE_TO_COMPLY;
	}

	struct node_avp *ans = NULL, **tail = &ans;
	add_out(&tail, AVP_SESSION_ID, id, strlen(id));
	add_out(&tail, AVP_ORIGIN_HOST, ORIGIN_HOST, strlen(ORIGIN_HOST));
	add_out(&tail, AVP_ORIGIN_REALM, ORIGIN_REALM, strlen(ORIGIN_REALM));
	add_out_u32(&tail, AVP_RESULT_CODE, rc);
	add_out_u32(&tail, AVP_CC_REQUEST_TYPE, type);
	add_out_u32(&tail, AVP_CC_REQUEST_NUMBER, num);
	if (give_grant) {
		uint8_t inner[12];
		size_t k = diam_put_u32(inner, AVP_CC_TIME, grant);
		add_out(&tail, AVP_GRANTED_SERVICE_UNIT, inner, k);
	}
	size_t n = serialise(ccr, ans, out, cap);
	free_avps(ans);
	free_avps(req);
	return n;
}

static struct engine *create(size_t max_sessions, size_t max_accounts)
{
	(void)max_accounts;
	struct engine *e = calloc(1, sizeof(*e));
	if (e)
		e->max_sessions = max_sessions;
	return e;
}

static int add_account(struct engine *e, const char *msisdn, uint32_t balance)
{
	if (strlen(msisdn) > MSISDN_MAX || find_account(e, msisdn))
		return -1;
	struct account *a = calloc(1, sizeof(*a));
	if (!a)
		return -1;
	strcpy(a->msisdn, msisdn);
	a->balance = balance;
	a->next = e->accounts;
	e->accounts = a;
	return 0;
}

static long balance(struct engine *e, const char *msisdn)
{
	struct account *a = find_account(e, msisdn);
	return a ? (long)a->balance : -1;
}

static size_t sessions(struct engine *e)
{
	return e->nsessions;
}

static void destroy(struct engine *e)
{
	while (e->sessions) {
		struct session *n = e->sessions->next;
		free(e->sessions);
		e->sessions = n;
	}
	while (e->accounts) {
		struct account *n = e->accounts->next;
		free(e->accounts);
		e->accounts = n;
	}
	free(e);
}

const struct engine_ops baseline_ops = {
	create, add_account, balance, sessions, handle, destroy, "baseline",
};
