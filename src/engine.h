/* SPDX-License-Identifier: MIT */
/* An online charging engine: answers CCR with CCA and keeps prepaid
 * balances. Two implementations share these exact rules and must produce
 * byte-identical answers; they differ only in data structures.
 *
 * Rules (time-based quota, seconds):
 *   INITIAL      unknown subscriber        -> 5030 USER_UNKNOWN
 *                session already exists    -> 5012 UNABLE_TO_COMPLY
 *                balance is 0              -> 4012 CREDIT_LIMIT_REACHED
 *                session table full        -> 5012
 *                else reserve min(requested, balance) and grant it
 *   UPDATE       unknown session           -> 5002 UNKNOWN_SESSION_ID
 *                debit min(used, reserved), return the rest to the balance,
 *                reserve min(requested, balance); 0 -> 4012 (session kept)
 *   TERMINATION  unknown session           -> 5002
 *                debit min(used, reserved), refund the rest, drop session
 *   malformed request (no Session-Id / CC-Request-Type) -> 5012
 *
 * CCA AVP order: Session-Id, Origin-Host, Origin-Realm, Result-Code,
 * CC-Request-Type, CC-Request-Number, [Granted-Service-Unit{CC-Time}]
 * (the last one only on success for INITIAL/UPDATE). */
#ifndef ENGINE_H
#define ENGINE_H

#include <stddef.h>
#include <stdint.h>

enum engine_kind { ENGINE_BASELINE, ENGINE_FAST };

struct engine;

struct engine_ops {
	struct engine *(*create)(size_t max_sessions, size_t max_accounts);
	int (*add_account)(struct engine *e, const char *msisdn, uint32_t balance);
	long (*balance)(struct engine *e, const char *msisdn); /* -1 if unknown */
	size_t (*sessions)(struct engine *e);
	/* Returns the CCA length written to out, or 0 if the request could not
	 * be parsed at the Diameter header level (it is then dropped). */
	size_t (*handle)(struct engine *e, const uint8_t *ccr, size_t len,
			 uint8_t *out, size_t cap);
	void (*destroy)(struct engine *e);
	const char *name;
};

extern const struct engine_ops baseline_ops;
extern const struct engine_ops fast_ops;

#define CCA_MAX 512
#define SESSION_ID_MAX 128
#define MSISDN_MAX 20

#endif
