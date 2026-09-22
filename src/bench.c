/* SPDX-License-Identifier: MIT */
/* charging-bench: drive both engines with the same call mix and report
 * credit-control messages handled per second.
 *
 * Call mix: `active` sessions stay open. Each step picks one, sends an
 * UPDATE, and every 4th update terminates it and opens a new one
 * (INITIAL). All CCRs are pre-built, so only the engine is timed. */
#define _POSIX_C_SOURCE 200809L
#include "diam.h"
#include "engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct msg {
	uint8_t buf[256];
	uint16_t len;
};

static double now_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static struct msg *build_workload(size_t active, size_t n, size_t subs)
{
	struct msg *w = malloc(n * sizeof(*w));
	uint32_t *gen = calloc(active, sizeof(*gen)), *num = calloc(active, sizeof(*num));
	char sid[64], msisdn[32];
	uint64_t r = 88172645463325252ULL;
	size_t k = 0;

	if (!w || !gen || !num)
		exit(1);
	/* open every session first */
	for (size_t s = 0; s < active && k < n; s++, k++) {
		snprintf(sid, sizeof(sid), "pcscf.example.org;%zu;%u", s, gen[s]);
		snprintf(msisdn, sizeof(msisdn), "9198%08zu", s % subs);
		w[k].len = (uint16_t)diam_build_ccr(w[k].buf, sid, CC_INITIAL, num[s]++,
						    msisdn, 60, 0, (uint32_t)k, (uint32_t)k);
	}
	while (k < n) {
		r ^= r << 13; r ^= r >> 7; r ^= r << 17;
		size_t s = r % active;
		snprintf(sid, sizeof(sid), "pcscf.example.org;%zu;%u", s, gen[s]);
		snprintf(msisdn, sizeof(msisdn), "9198%08zu", s % subs);
		int end = num[s] % 4 == 0;
		w[k].len = (uint16_t)diam_build_ccr(w[k].buf, sid, end ? CC_TERMINATION : CC_UPDATE,
						    num[s]++, msisdn, 60, 30, (uint32_t)k, (uint32_t)k);
		k++;
		if (end && k < n) { /* start the next call on this slot */
			gen[s]++;
			num[s] = 0;
			snprintf(sid, sizeof(sid), "pcscf.example.org;%zu;%u", s, gen[s]);
			w[k].len = (uint16_t)diam_build_ccr(w[k].buf, sid, CC_INITIAL, num[s]++,
							    msisdn, 60, 0, (uint32_t)k, (uint32_t)k);
			k++;
		}
	}
	free(gen);
	free(num);
	return w;
}

static double run(const struct engine_ops *ops, const struct msg *w, size_t n,
		  size_t active, size_t subs, unsigned *fail)
{
	struct engine *e = ops->create(active, subs);
	char msisdn[32];
	uint8_t out[CCA_MAX];
	for (size_t i = 0; i < subs; i++) {
		snprintf(msisdn, sizeof(msisdn), "9198%08zu", i);
		ops->add_account(e, msisdn, 4000000000u);
	}
	*fail = 0;
	double t0 = now_s();
	for (size_t i = 0; i < n; i++) {
		size_t len = ops->handle(e, w[i].buf, w[i].len, out, sizeof(out));
		/* Result-Code sits right after Session-Id + template; just spot-check */
		if (len == 0)
			(*fail)++;
	}
	double dt = now_s() - t0;
	ops->destroy(e);
	return n / dt;
}

int main(int argc, char **argv)
{
	size_t sizes[] = { 100, 1000, 10000 };
	size_t n = argc > 1 ? strtoul(argv[1], NULL, 10) : 200000;

	printf("%-10s %14s %14s %8s\n", "active", "baseline msg/s", "fast msg/s", "ratio");
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		size_t active = sizes[i], subs = active;
		size_t count = active >= 10000 ? n / 4 : n; /* baseline is O(n) per lookup */
		struct msg *w = build_workload(active, count, subs);
		unsigned f1, f2;
		double b = run(&baseline_ops, w, count, active, subs, &f1);
		double f = run(&fast_ops, w, count, active, subs, &f2);
		printf("%-10zu %14.0f %14.0f %7.1fx%s\n", active, b, f, f / b,
		       f1 || f2 ? "  (dropped messages!)" : "");
		free(w);
	}
	return 0;
}
