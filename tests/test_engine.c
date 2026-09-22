/* SPDX-License-Identifier: MIT */
#include "../src/diam.h"
#include "../src/engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t result_code(const uint8_t *cca, size_t len)
{
	const uint8_t *p = cca + DIAM_HDR_LEN, *end = cca + len;
	struct avp a;
	while (diam_avp_next(&p, end, &a) == 1)
		if (a.code == AVP_RESULT_CODE)
			return rd32(a.data);
	return 0;
}

static long granted(const uint8_t *cca, size_t len)
{
	const uint8_t *p = cca + DIAM_HDR_LEN, *end = cca + len;
	struct avp a;
	while (diam_avp_next(&p, end, &a) == 1)
		if (a.code == AVP_GRANTED_SERVICE_UNIT)
			return rd32(a.data + 8);
	return -1;
}

static void rules(const struct engine_ops *ops)
{
	uint8_t req[512], cca[CCA_MAX];
	struct engine *e = ops->create(2, 4);
	size_t n;

	CHECK(ops->add_account(e, "919800000001", 100) == 0);
	CHECK(ops->add_account(e, "919800000001", 5) == -1); /* duplicate */
	CHECK(ops->add_account(e, "919800000002", 0) == 0);

	/* INITIAL: grant is capped by balance and reserved up front */
	n = diam_build_ccr(req, "s1", CC_INITIAL, 0, "919800000001", 60, 0, 1, 1);
	n = ops->handle(e, req, n, cca, sizeof(cca));
	CHECK(result_code(cca, n) == DIAMETER_SUCCESS && granted(cca, n) == 60);
	CHECK(ops->balance(e, "919800000001") == 40);
	CHECK(cca[4] == 0 && rd32(cca + 12) == 1); /* answer flag, hop-by-hop echoed */

	/* duplicate INITIAL on the same session */
	n = diam_build_ccr(req, "s1", CC_INITIAL, 0, "919800000001", 60, 0, 2, 2);
	n = ops->handle(e, req, n, cca, sizeof(cca));
	CHECK(result_code(cca, n) == DIAMETER_UNABLE_TO_COMPLY);

	/* UPDATE: used 50 of 60, 10 refunded, then min(60, 50) granted */
	n = diam_build_ccr(req, "s1", CC_UPDATE, 1, "919800000001", 60, 50, 3, 3);
	n = ops->handle(e, req, n, cca, sizeof(cca));
	CHECK(result_code(cca, n) == DIAMETER_SUCCESS && granted(cca, n) == 50);
	CHECK(ops->balance(e, "919800000001") == 0);

	/* UPDATE with nothing left: 4012, no grant, session kept */
	n = diam_build_ccr(req, "s1", CC_UPDATE, 2, "919800000001", 60, 50, 4, 4);
	n = ops->handle(e, req, n, cca, sizeof(cca));
	CHECK(result_code(cca, n) == DIAMETER_CREDIT_LIMIT_REACHED && granted(cca, n) == -1);
	CHECK(ops->sessions(e) == 1);

	/* over-reported usage is clamped to what was reserved (0 now) */
	n = diam_build_ccr(req, "s1", CC_TERMINATION, 3, "919800000001", 0, 999, 5, 5);
	n = ops->handle(e, req, n, cca, sizeof(cca));
	CHECK(result_code(cca, n) == DIAMETER_SUCCESS && granted(cca, n) == -1);
	CHECK(ops->sessions(e) == 0 && ops->balance(e, "919800000001") == 0);

	n = diam_build_ccr(req, "nope", CC_UPDATE, 1, "919800000001", 1, 1, 6, 6);
	CHECK(result_code(cca, ops->handle(e, req, n, cca, sizeof(cca))) == DIAMETER_UNKNOWN_SESSION_ID);
	n = diam_build_ccr(req, "s2", CC_INITIAL, 0, "919899999999", 1, 0, 7, 7);
	CHECK(result_code(cca, ops->handle(e, req, n, cca, sizeof(cca))) == DIAMETER_USER_UNKNOWN);
	n = diam_build_ccr(req, "s2", CC_INITIAL, 0, "919800000002", 1, 0, 8, 8);
	CHECK(result_code(cca, ops->handle(e, req, n, cca, sizeof(cca))) == DIAMETER_CREDIT_LIMIT_REACHED);

	/* not a CCR at all: dropped */
	CHECK(ops->handle(e, req, 10, cca, sizeof(cca)) == 0);
	ops->destroy(e);
}

/* ---- differential test: same traffic through both engines ---- */

static uint64_t rng = 0x243F6A8885A308D3ULL;
static uint32_t rnd(uint32_t n)
{
	rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
	return (uint32_t)(rng % n);
}

static void differential(void)
{
	enum { SUBS = 300, SESS = 400, MSGS = 200000 };
	struct engine *b = baseline_ops.create(SESS / 2, SUBS);
	struct engine *f = fast_ops.create(SESS / 2, SUBS); /* table fills up sometimes */
	char msisdn[32], sid[64];
	uint8_t req[512], ca[CCA_MAX], cf[CCA_MAX];
	uint32_t reqnum[SESS] = { 0 };

	for (int i = 0; i < SUBS; i++) {
		snprintf(msisdn, sizeof(msisdn), "9198%08d", i);
		uint32_t bal = rnd(4) == 0 ? 0 : rnd(5000);
		baseline_ops.add_account(b, msisdn, bal);
		fast_ops.add_account(f, msisdn, bal);
	}

	size_t mism = 0, dropped = 0;
	for (uint32_t m = 0; m < MSGS; m++) {
		uint32_t s = rnd(SESS);
		snprintf(sid, sizeof(sid), "pcscf.example.org;%u;%u", s, s * 7919u);
		snprintf(msisdn, sizeof(msisdn), "9198%08u", rnd(SUBS + 20)); /* some unknown */
		uint32_t type = 1 + rnd(3);
		size_t n = diam_build_ccr(req, sid, type, reqnum[s]++, msisdn,
					  rnd(300), rnd(400), m, m ^ 0xABCDu);

		switch (rnd(40)) { /* inject malformed messages */
		case 0: wr24(req + DIAM_HDR_LEN + 5, 4000); break;          /* AVP overruns */
		case 1: wr32(req + DIAM_HDR_LEN, 999); break;               /* no Session-Id */
		case 2: n = (n - 4) & ~(size_t)3; diam_finish(req, n); break; /* truncated */
		case 3: req[4] = 0; break;                                   /* not a request */
		default: break;
		}

		size_t nb = baseline_ops.handle(b, req, n, ca, sizeof(ca));
		size_t nf = fast_ops.handle(f, req, n, cf, sizeof(cf));
		if (nb == 0 && nf == 0) {
			dropped++;
			continue;
		}
		if (nb != nf || memcmp(ca, cf, nb) != 0) {
			if (mism++ < 3)
				fprintf(stderr, "mismatch at message %u (type %u)\n", m, type);
		}
	}
	CHECK(mism == 0);
	CHECK(dropped > 0);
	CHECK(baseline_ops.sessions(b) == fast_ops.sessions(f));
	for (int i = 0; i < SUBS; i++) {
		snprintf(msisdn, sizeof(msisdn), "9198%08d", i);
		CHECK(baseline_ops.balance(b, msisdn) == fast_ops.balance(f, msisdn));
	}
	printf("differential: %d messages, %zu dropped as non-CCR, %zu mismatches\n",
	       MSGS, dropped, mism);
	baseline_ops.destroy(b);
	fast_ops.destroy(f);
}

int main(void)
{
	rules(&baseline_ops);
	rules(&fast_ops);
	differential();
	if (fails) {
		fprintf(stderr, "%d check(s) failed\n", fails);
		return 1;
	}
	printf("all tests passed\n");
	return 0;
}
