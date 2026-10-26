#!/usr/bin/env bash
# One place for all manual checks. Usage: ./check.sh test | bench | egress | all
PY="${PYTHON:-./venv/bin/python}"
if [ ! -f "$PY" ] && [ ! -x "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PY="python3"
  elif command -v python >/dev/null 2>&1; then
    PY="python"
  fi
fi
echo "[check.sh] Using Python interpreter: $PY"
case "$1" in
  test)  $PY -m pytest -q 2>&1 | tail -3 ;;
  bench) $PY main.py --benchmark --offline 2>&1 | tail -3 ;;
  egress)
    $PY - << 'PYEOF'
import json, uuid
u = uuid.uuid4().hex[:8]
json.dump({
  "email_id": "em_chk_" + u, "message_id": "<chk-" + u + "@acme-corp.com>",
  "thread_id": "th_chk_" + u, "sender_email": "john.smith@acme-corp.com",
  "sender_domain": "acme-corp.com",
  "email_subject": "Refund for John Smith, card 4111 1111 1111 1111, contact maria.lopez@gmail.com",
  "email_body": "Hi, I'm John Smith. Our Postgres pool is exhausted since this morning. Please call me."
}, open("/tmp/sample_email.json", "w"))
PYEOF
    JEV_API_KEY=fake-key GROQ_API_KEY=fake-key $PY tools/egress_check.py \
      --forbid "John Smith" --forbid "john.smith" --forbid "maria.lopez" --forbid "4111" \
      -- main.py --input /tmp/sample_email.json ;;
  all) "$0" test; "$0" bench; "$0" egress ;;
  *) echo "usage: ./check.sh test | bench | egress | all" ;;
esac
