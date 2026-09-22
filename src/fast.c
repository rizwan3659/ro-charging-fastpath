/* SPDX-License-Identifier: MIT */
/* Fast engine. Same rules as baseline.c; the changes are all in the data
 * path:
 *   - AVPs are read in place (struct avp points into the request buffer)
 *   - sessions and accounts are in open-addressing hash tables
 *   - sessions come from a preallocated pool, so the hot path never mallocs
 *   - the constant part of every answer (Origin-Host/Realm) is encoded once
 *     and copied; numeric AVPs are written straight into the output */
#include "diam.h"
#include "engine.h"

#include <stdlib.h>
#include <string.h>

#define EMPTY UINT32_MAX

struct account {
	char msisdn[MSISDN_MAX + 1];
	uint8_t len;
	uint32_t balance;
};

struct session {
	char id[SESSION_ID_MAX];
	uint8_t id_len;
	uint32_t acct;       /* index into accounts */
	uint32_t reserved;
	uint32_t next_free;
};

struct table {           /* linear probing, backward-shift deletion */
	uint32_t *slot;      /* index into the object array, or EMPTY */
	size_t mask;
};

struct engine {
	struct account *acc;
	size_t nacc, max_acc;
	struct table acc_t;

	struct session *ses;
	size_t nses, max_ses;
	uint32_t free_head;
	struct table ses_t;

	uint8_t tmpl[64];     /* Origin-Host + Origin-Realm, pre-encoded */
	size_t tmpl_len;
};

static uint64_t hash(const void *p, size_t n)
{
	const uint8_t *b = p;
	uint64_t h = 1469598103934665603ULL; /* FNV-1a */
	for (size_t i = 0; i < n; i++)
		h = (h ^ b[i]) * 1099511628211ULL;
	return h;
}

static int table_init(struct table *t, size_t n)
{
	size_t cap = 16;
	while (cap < n * 2)
		cap <<= 1;
	t->slot = malloc(cap * sizeof(*t->slot));
	if (!t->slot)
		return -1;
	memset(t->slot, 0xff, cap * sizeof(*t->slot));
	t->mask = cap - 1;
	return 0;
}

/* ---- accounts ---- */

static size_t acc_find(struct engine *e, const void *k, size_t n)
{
	for (size_t i = hash(k, n) & e->acc_t.mask;; i = (i + 1) & e->acc_t.mask) {
		uint32_t x = e->acc_t.slot[i];
		if (x == EMPTY)
			return i;
		if (e->acc[x].len == n && memcmp(e->acc[x].msisdn, k, n) == 0)
			return i;
	}
}

/* ---- sessions ---- */

static size_t ses_find(struct engine *e, const void *k, size_t n)
{
	for (size_t i = hash(k, n) & e->ses_t.mask;; i = (i + 1) & e->ses_t.mask) {
		uint32_t x = e->ses_t.slot[i];
		if (x == EMPTY)
			return i;
		if (e->ses[x].id_len == n && memcmp(e->ses[x].id, k, n) == 0)
			return i;
	}
}

static void ses_remove(struct engine *e, size_t i)
{
	struct table *t = &e->ses_t;
	uint32_t x = t->slot[i];

	e->ses[x].next_free = e->free_head;
	e->free_head = x;
	e->nses--;

	/* Backward-shift: pull later entries of the same probe run into the
	 * hole so lookups never need tombstones. */
	size_t j = i;
	for (;;) {
		t->slot[i] = EMPTY;
		for (;;) {
			j = (j + 1) & t->mask;
			if (t->slot[j] == EMPTY)
				return;
			struct session *s = &e->ses[t->slot[j]];
			size_t home = hash(s->id, s->id_len) & t->mask;
			/* can the entry at j move to i? only if home is not in (i, j] */
			if (i <= j ? (home <= i || home > j) : (home <= i && home > j))
				break;
		}
		t->slot[i] = t->slot[j];
		i = j;
	}
}

/* ---- request parsing (zero-copy) ---- */

struct ccr {
	struct avp sid, type, num, sub, rsu, usu;
	int have_sid, have_type, have_num, have_sub, have_rsu, have_usu;
	int err;
};

static void parse(const uint8_t *p, const uint8_t *end, struct ccr *c)
{
	struct avp a;
	int r;
	memset(c, 0, sizeof(*c));
	while ((r = diam_avp_next(&p, end, &a)) == 1) {
		/* first occurrence wins */
		switch (a.code) {
		case AVP_SESSION_ID: if (!c->have_sid) { c->sid = a; c->have_sid = 1; } break;
		case AVP_CC_REQUEST_TYPE: if (!c->have_type) { c->type = a; c->have_type = 1; } break;
		case AVP_CC_REQUEST_NUMBER: if (!c->have_num) { c->num = a; c->have_num = 1; } break;
		case AVP_SUBSCRIPTION_ID: if (!c->have_sub) { c->sub = a; c->have_sub = 1; } break;
		case AVP_REQUESTED_SERVICE_UNIT: if (!c->have_rsu) { c->rsu = a; c->have_rsu = 1; } break;
		case AVP_USED_SERVICE_UNIT: if (!c->have_usu) { c->usu = a; c->have_usu = 1; } break;
		default: break;
		}
	}
	c->err = r < 0;
}

static int u32_of(int have, const struct avp *a, uint32_t *v)
{
	if (!have || a->len != 4)
		return 0;
	*v = rd32(a->data);
	return 1;
}

/* First inner AVP with `code` inside grouped AVP g; fails on malformed. */
static int inner(const struct avp *g, uint32_t code, struct avp *out)
{
	const uint8_t *p = g->data, *end = g->data + g->len;
	struct avp a;
	int r, found = 0;
	while ((r = diam_avp_next(&p, end, &a)) == 1)
		if (!found && a.code == code) {
			*out = a;
			found = 1;
		}
	return r == 0 && found;
}

static int unit_of(int have, const struct avp *g, uint32_t *v)
{
	struct avp t;
	return have && inner(g, AVP_CC_TIME, &t) && u32_of(1, &t, v);
}

/* ---- answer ---- */

static uint8_t *put_u32(uint8_t *o, uint32_t code, uint32_t v)
{
	wr32(o, code);
	o[4] = DIAM_AVP_FLAG_M;
	wr24(o + 5, 12);
	wr32(o + 8, v);
	return o + 12;
}

static size_t answer(struct engine *e, const uint8_t *req, const uint8_t *sid,
		     size_t sid_len, uint32_t rc, uint32_t type, uint32_t num,
		     int give_grant, uint32_t grant, uint8_t *out, size_t cap)
{
	size_t need = DIAM_HDR_LEN + pad4(DIAM_AVP_HDR + sid_len) + e->tmpl_len +
		      36 + (give_grant ? 20 : 0);
	if (need > cap)
		return 0;

	memcpy(out, req, DIAM_HDR_LEN);   /* version, cmd, app, hbh, e2e */
	out[4] = 0;                       /* answer: clear R flag */
	uint8_t *o = out + DIAM_HDR_LEN;
	o += diam_put_avp(o, AVP_SESSION_ID, sid, sid_len);
	memcpy(o, e->tmpl, e->tmpl_len);
	o += e->tmpl_len;
	o = put_u32(o, AVP_RESULT_CODE, rc);
	o = put_u32(o, AVP_CC_REQUEST_TYPE, type);
	o = put_u32(o, AVP_CC_REQUEST_NUMBER, num);
	if (give_grant) {
		wr32(o, AVP_GRANTED_SERVICE_UNIT);
		o[4] = DIAM_AVP_FLAG_M;
		wr24(o + 5, 20);
		o = put_u32(o + 8, AVP_CC_TIME, grant);
	}
	size_t n = (size_t)(o - out);
	diam_finish(out, n);
	return n;
}

static size_t handle(struct engine *e, const uint8_t *ccr, size_t len,
		     uint8_t *out, size_t cap)
{
	size_t mlen = diam_check_ccr(ccr, len);
	if (!mlen)
		return 0;

	struct ccr c;
	parse(ccr + DIAM_HDR_LEN, ccr + mlen, &c);

	uint32_t type = 0, num = 0, rc = DIAMETER_SUCCESS, grant = 0;
	int give_grant = 0;
	const uint8_t *sid = (const uint8_t *)"";
	size_t sid_len = 0;

	if (c.have_sid && c.sid.len <= SESSION_ID_MAX) {
		sid = c.sid.data;
		sid_len = c.sid.len;
	}
	u32_of(c.have_num, &c.num, &num);

	if (c.err || !c.have_sid || c.sid.len > SESSION_ID_MAX ||
	    !u32_of(c.have_type, &c.type, &type)) {
		rc = DIAMETER_UNABLE_TO_COMPLY;
	} else if (type == CC_INITIAL) {
		struct avp d;
		uint32_t want = 0;
		uint32_t ai = EMPTY;
		if (c.have_sub && inner(&c.sub, AVP_SUBSCRIPTION_ID_DATA, &d) &&
		    d.len <= MSISDN_MAX)
			ai = e->acc_t.slot[acc_find(e, d.data, d.len)];
		unit_of(c.have_rsu, &c.rsu, &want);

		size_t si = ses_find(e, sid, sid_len);
		if (ai == EMPTY)
			rc = DIAMETER_USER_UNKNOWN;
		else if (e->ses_t.slot[si] != EMPTY || e->nses >= e->max_ses)
			rc = DIAMETER_UNABLE_TO_COMPLY;
		else if (e->acc[ai].balance == 0)
			rc = DIAMETER_CREDIT_LIMIT_REACHED;
		else {
			struct account *a = &e->acc[ai];
			uint32_t x = e->free_head;
			struct session *s = &e->ses[x];
			e->free_head = s->next_free;
			grant = want < a->balance ? want : a->balance;
			a->balance -= grant;
			memcpy(s->id, sid, sid_len);
			s->id_len = (uint8_t)sid_len;
			s->acct = ai;
			s->reserved = grant;
			e->ses_t.slot[si] = x;
			e->nses++;
			give_grant = 1;
		}
	} else if (type == CC_UPDATE || type == CC_TERMINATION) {
		size_t si = ses_find(e, sid, sid_len);
		uint32_t x = e->ses_t.slot[si];
		if (x == EMPTY) {
			rc = DIAMETER_UNKNOWN_SESSION_ID;
		} else {
			struct session *s = &e->ses[x];
			struct account *a = &e->acc[s->acct];
			uint32_t used = 0, want = 0;
			unit_of(c.have_usu, &c.usu, &used);
			if (used > s->reserved)
				used = s->reserved;
			a->balance += s->reserved - used;
			s->reserved = 0;
			if (type == CC_TERMINATION) {
				ses_remove(e, si);
			} else {
				unit_of(c.have_rsu, &c.rsu, &want);
				grant = want < a->balance ? want : a->balance;
				if (grant == 0) {
					rc = DIAMETER_CREDIT_LIMIT_REACHED;
				} else {
					a->balance -= grant;
					s->reserved = grant;
					give_grant = 1;
				}
			}
		}
	} else {
		rc = DIAMETER_UNABLE_TO_COMPLY;
	}

	return answer(e, ccr, sid, sid_len, rc, type, num, give_grant, grant, out, cap);
}

static void destroy(struct engine *e)
{
	if (!e)
		return;
	free(e->acc);
	free(e->acc_t.slot);
	free(e->ses);
	free(e->ses_t.slot);
	free(e);
}

static struct engine *create(size_t max_sessions, size_t max_accounts)
{
	struct engine *e = calloc(1, sizeof(*e));
	if (!e || max_sessions == 0 || max_sessions >= EMPTY || max_accounts >= EMPTY)
		goto fail;
	e->max_ses = max_sessions;
	e->max_acc = max_accounts;
	e->acc = calloc(max_accounts ? max_accounts : 1, sizeof(*e->acc));
	e->ses = calloc(max_sessions, sizeof(*e->ses));
	if (!e->acc || !e->ses || table_init(&e->acc_t, max_accounts) ||
	    table_init(&e->ses_t, max_sessions))
		goto fail;
	for (size_t i = 0; i < max_sessions; i++)
		e->ses[i].next_free = i + 1 < max_sessions ? (uint32_t)(i + 1) : EMPTY;
	e->free_head = 0;

	e->tmpl_len = diam_put_avp(e->tmpl, AVP_ORIGIN_HOST, ORIGIN_HOST, strlen(ORIGIN_HOST));
	e->tmpl_len += diam_put_avp(e->tmpl + e->tmpl_len, AVP_ORIGIN_REALM,
				    ORIGIN_REALM, strlen(ORIGIN_REALM));
	return e;
fail:
	destroy(e);
	return NULL;
}

static int add_account(struct engine *e, const char *msisdn, uint32_t balance)
{
	size_t n = strlen(msisdn);
	if (n > MSISDN_MAX || e->nacc >= e->max_acc)
		return -1;
	size_t i = acc_find(e, msisdn, n);
	if (e->acc_t.slot[i] != EMPTY)
		return -1;
	struct account *a = &e->acc[e->nacc];
	memcpy(a->msisdn, msisdn, n);
	a->len = (uint8_t)n;
	a->balance = balance;
	e->acc_t.slot[i] = (uint32_t)e->nacc++;
	return 0;
}

static long balance(struct engine *e, const char *msisdn)
{
	uint32_t x = e->acc_t.slot[acc_find(e, msisdn, strlen(msisdn))];
	return x == EMPTY ? -1 : (long)e->acc[x].balance;
}

static size_t sessions(struct engine *e)
{
	return e->nses;
}

const struct engine_ops fast_ops = {
	create, add_account, balance, sessions, handle, destroy, "fast",
};
