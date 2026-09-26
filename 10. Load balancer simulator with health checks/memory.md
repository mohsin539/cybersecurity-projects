# AegisLB — Persistent Memory (preservation artifact)

*Purpose:* durable cross-session record of configuration baseline, operator notes, and a chronological decision/event log. Rebuilt from the cache on every flush; append-only semantics for the log (no in-place edits of historical entries).

Last updated (UTC): 2026-09-17T07:51:57Z  |  Current run: 194ebde0f8cf

## Configuration Baseline

| Setting | Value |
|---|---|
| seed | 41394 |
| rps | 60.0 |
| speed | 1.0 |
| policy | LEAST_CONNECTIONS |
| arrival_model | POISSON |
| health_sources | 2 |

## Health Thresholds (baseline)

| Threshold | Default | Role |
|---|---|---|
| failThreshold (leaves HEALTHY) | 3 consecutive failures | anti-flap hysteresis |
| passThreshold (recovers) | 2 consecutive passes | anti-flap hysteresis |
| graceDegradedMs | 1500 | slow-lane detection margin |
| backoffMaxMs | 60000 | probe backoff cap |
| quarantineThreshold | 3 | repeated failures ⇒ QUARANTINED |

## Operator Notes

_No notes recorded yet._

## Decision & Event Log (latest 200)

| t(s) | eid | type | severity | detail |
|---|---|---|---|---|
| 5.35 | 435 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-703b0566"} |
| 5.4 | 436 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3f4276fd"} |
| 5.4 | 437 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-75e9a62e"} |
| 5.4 | 438 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-576b6515"} |
| 5.4 | 439 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ecb3720f"} |
| 5.4 | 440 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e8718908"} |
| 5.4 | 441 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3a65b29d"} |
| 5.4 | 442 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-686b2d1a"} |
| 5.45 | 443 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bbba0924"} |
| 5.5 | 444 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4849e0b2"} |
| 5.5 | 445 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d74941a8"} |
| 5.5 | 446 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-aeeb89aa"} |
| 5.55 | 447 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ef8f77e0"} |
| 5.55 | 448 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-641071f6"} |
| 5.55 | 449 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-1fe4653f"} |
| 5.55 | 450 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d3425c3a"} |
| 5.55 | 451 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-66b08f97"} |
| 5.55 | 452 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-84336241"} |
| 5.6 | 453 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3a7ce2cb"} |
| 5.6 | 454 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-820e4315"} |
| 5.6 | 455 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d9b72526"} |
| 5.6 | 456 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3e07928d"} |
| 5.6 | 457 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bb8b7474"} |
| 5.65 | 458 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6d3cf7cb"} |
| 5.65 | 459 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-b1759c23"} |
| 5.65 | 460 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-64fd8212"} |
| 5.7 | 461 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6ceb170b"} |
| 5.7 | 462 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-06e7c145"} |
| 5.7 | 463 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e8c548e5"} |
| 5.7 | 464 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-453c0d37"} |
| 5.7 | 465 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-8b6b631c"} |
| 5.7 | 466 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-388ebedb"} |
| 5.7 | 467 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-5a6bfc1c"} |
| 5.7 | 468 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d6c41c85"} |
| 5.75 | 469 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4b49ee1c"} |
| 5.75 | 470 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-90f9964b"} |
| 5.8 | 471 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-c388caa5"} |
| 5.8 | 472 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3ad64650"} |
| 5.85 | 473 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-71d7ba93"} |
| 5.85 | 474 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6ce3246a"} |
| 5.85 | 475 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-039afe29"} |
| 5.85 | 476 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-91522baa"} |
| 5.85 | 477 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-799ad41e"} |
| 5.9 | 478 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-2bf46673"} |
| 5.9 | 479 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4f590454"} |
| 5.9 | 480 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-8661655b"} |
| 5.9 | 481 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-2805cd04"} |
| 5.9 | 482 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-049134fb"} |
| 5.95 | 483 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bad2c50f"} |
| 5.95 | 484 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-67abbf35"} |
| 5.95 | 485 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-26bc2583"} |
| 6.0 | 486 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-15b60e6c"} |
| 6.0 | 487 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ba89b29a"} |
| 6.05 | 488 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-952a934c"} |
| 6.05 | 489 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d9538531"} |
| 6.05 | 490 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-060d3983"} |
| 6.05 | 491 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bb04a435"} |
| 6.1 | 492 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6f3b32d6"} |
| 6.1 | 493 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-10de0856"} |
| 6.1 | 494 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d6a99934"} |
| 6.1 | 495 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4f8db3c0"} |
| 6.1 | 496 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-49a1169c"} |
| 6.1 | 497 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-961c11e8"} |
| 6.1 | 498 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-880604b8"} |
| 6.15 | 500 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4588e56f"} |
| 6.15 | 501 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-c984d6d5"} |
| 6.15 | 502 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ca28f6e1"} |
| 6.15 | 503 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e63bfa55"} |
| 6.15 | 504 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-259ba581"} |
| 6.15 | 505 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-51d4ac9d"} |
| 6.15 | 506 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-277f9626"} |
| 6.15 | 507 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-64969500"} |
| 6.2 | 508 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d298e51c"} |
| 6.2 | 509 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-82dc839b"} |
| 6.2 | 510 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6d540766"} |
| 6.25 | 511 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-499b6d18"} |
| 6.25 | 512 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-688240f2"} |
| 6.25 | 513 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-0d47644c"} |
| 6.25 | 514 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-abdacf60"} |
| 6.3 | 515 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-a4385f92"} |
| 6.3 | 516 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6cf01325"} |
| 6.3 | 517 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-05b10de5"} |
| 6.3 | 518 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-67f1c425"} |
| 6.3 | 519 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ee35e24d"} |
| 6.35 | 520 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-aefba333"} |
| 6.35 | 521 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-da1a5cbc"} |
| 6.35 | 522 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-f639ae5d"} |
| 6.35 | 523 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6fac30cd"} |
| 6.4 | 524 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bc05a2e9"} |
| 6.4 | 525 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-0b04beab"} |
| 6.4 | 526 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e34992e7"} |
| 6.4 | 527 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-9d8f10fb"} |
| 6.4 | 528 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-59a4b33d"} |
| 6.4 | 529 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-df77dd22"} |
| 6.4 | 530 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-44421353"} |
| 6.45 | 531 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-c66e26d4"} |
| 6.45 | 532 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-86989266"} |
| 6.45 | 533 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4beb8812"} |
| 6.45 | 534 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-538a6ce3"} |
| 6.45 | 535 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-bb2aa3b3"} |
| 6.5 | 536 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-f8ec9f03"} |
| 6.5 | 537 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-aaf6fe43"} |
| 6.5 | 538 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-a13f33ae"} |
| 6.55 | 539 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-acb2a0ea"} |
| 6.55 | 540 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-001275e9"} |
| 6.6 | 541 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-5826cc5c"} |
| 6.6 | 542 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6aba8e31"} |
| 6.6 | 543 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-691ad7cf"} |
| 6.65 | 544 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6ae5c4aa"} |
| 6.65 | 545 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-f77660cf"} |
| 6.65 | 546 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d6b24ade"} |
| 6.65 | 547 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4446cde5"} |
| 6.65 | 548 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-01d7af49"} |
| 6.7 | 549 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-84f51e1a"} |
| 6.7 | 550 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ba78fb5c"} |
| 6.7 | 551 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-954be3de"} |
| 6.7 | 552 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-b28b404b"} |
| 6.7 | 553 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-261805e2"} |
| 6.75 | 554 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-27ae506e"} |
| 6.75 | 555 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-8c7c2e85"} |
| 6.75 | 556 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-108ddcec"} |
| 6.75 | 557 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-718e7f3e"} |
| 6.8 | 558 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-6f00bae8"} |
| 6.8 | 559 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-0e118c96"} |
| 6.8 | 560 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e5b09924"} |
| 6.8 | 561 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-a5dbad7b"} |
| 6.85 | 562 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-09f122a5"} |
| 6.85 | 563 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-63e8d96f"} |
| 6.85 | 564 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-a1a27ecf"} |
| 6.85 | 565 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-b2916240"} |
| 6.9 | 566 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-ec38cc6f"} |
| 6.9 | 567 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-af192f16"} |
| 6.9 | 568 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-c20e670f"} |
| 6.9 | 569 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-69737fbb"} |
| 6.9 | 570 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-9877ddc7"} |
| 6.95 | 571 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-02a99083"} |
| 6.95 | 572 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-5caaa6cc"} |
| 6.95 | 573 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d341c7c5"} |
| 7.0 | 574 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-39658e1b"} |
| 7.0 | 575 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-439af135"} |
| 7.0 | 576 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d477da8e"} |
| 7.05 | 577 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3c0ff731"} |
| 7.05 | 578 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-96647a12"} |
| 7.05 | 579 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-7af1d2c5"} |
| 7.05 | 580 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d3b77012"} |
| 7.05 | 581 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-e5255b5f"} |
| 7.05 | 582 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-4e460e0d"} |
| 7.05 | 583 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-3ee04f40"} |
| 7.1 | 584 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-57548715"} |
| 7.1 | 585 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-0cc8b5ee"} |
| 7.1 | 586 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-fce63d71"} |
| 7.15 | 587 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-1082a1fa"} |
| 7.15 | 588 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-b2248844"} |
| 7.15 | 589 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-551e5226"} |
| 7.15 | 590 | SESSION_REJECT | warn | {"reason": "no_eligible", "status": 503, "token": "CLI-d8da1ece"} |
| 7.15 | 591 | STATE_TRANSITION | info | {"backend": "b-14b3151a", "from": "BOOTING", "reason": "probes_stable", "to": "HEALTHY"} |
| 8.35 | 779 | STATE_TRANSITION | info | {"backend": "b-8399038b", "from": "BOOTING", "reason": "probes_stable", "to": "HEALTHY"} |
| 9.25 | 921 | STATE_TRANSITION | info | {"backend": "b-64533c90", "from": "BOOTING", "reason": "probes_stable", "to": "HEALTHY"} |
| 9.8 | 999 | STATE_TRANSITION | info | {"backend": "b-5e71c3a5", "from": "BOOTING", "reason": "probes_stable", "to": "HEALTHY"} |
| 29.6 | 4081 | RUN | info | {"action": "stopped", "run_id": "20359566071d"} |
| 96.75 | 11054 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 103.6 | 11900 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 207.2 | 24366 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 209.85 | 24683 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 684.75 | 81075 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 688.9 | 81656 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 698.1 | 82913 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 704.05 | 83597 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 815.25 | 97039 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 820.3 | 97680 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1041.35 | 124003 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1047.4 | 124733 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1050.4 | 125058 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1052.45 | 125289 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1056.95 | 125873 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1062.6 | 126553 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1294.35 | 154198 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1298.95 | 154715 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1426.5 | 170002 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1433.25 | 170790 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 1536.95 | 183220 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 1540.15 | 183640 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 2456.2 | 292430 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 2462.6 | 293210 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 2824.3 | 336555 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 2830.1 | 337292 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3007.55 | 358739 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3011.5 | 359170 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3017.7 | 359920 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3021.7 | 360441 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3052.1 | 364002 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3057.0 | 364612 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3466.9 | 413627 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3471.5 | 414212 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3473.6 | 414495 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3476.6 | 414814 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3514.45 | 419357 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3516.75 | 419613 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |
| 3546.45 | 423119 | STATE_TRANSITION | warn | {"backend": "b-21caee80", "from": "HEALTHY", "reason": "passive_slowlane", "to": "DEGRADED"} |
| 3551.75 | 423700 | STATE_TRANSITION | info | {"backend": "b-21caee80", "from": "DEGRADED", "reason": "recovered_margin", "to": "HEALTHY"} |

## Preservation & Governance

- Cache artifact: `D:\AI Masterclass\Project\Track-2\10. Load balancer simulator with health checks\.aegislb_cache.json` (JSON, append-augmented).
- Retention per docs/01 §10 (decision traces 90d; audit 1y).
- Tamper-evident audit lives in `security.md` §Audit Chain (SHA-256 chained).

---
