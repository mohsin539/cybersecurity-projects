"""Sandbox layer: mandatory isolation for all untrusted-content jobs (ARCHITECTURE.md §3.5).

CODEOWNERS-protected. Security invariants:
1. Every job carries a Policy; deny-by-default.
2. Network egress is blocked inside analysis children (socket null-route).
3. File writes outside the job scratch dir are blocked (open() guard).
4. Timeout/resource breach => kill process tree; fail closed, never fail open.
"""
