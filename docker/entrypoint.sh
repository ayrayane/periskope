#!/bin/sh
set -e
role="$1"; shift || true
case "$role" in
  api) exec uvicorn periskope_api.app:app --host 0.0.0.0 --port 8000 --proxy-headers --no-server-header "$@" ;;
  scheduler) exec uvicorn periskope_scheduler.app:app --host 0.0.0.0 --port 8001 --no-server-header "$@" ;;
  collector) exec arq periskope_collector.worker.WorkerSettings "$@" ;;
  migrate) exec alembic -c "$(python -c 'import os, periskope_db; print(os.path.dirname(periskope_db.__file__))')/alembic.ini" upgrade head ;;
  *) echo "usage: api | scheduler | collector | migrate" >&2; exit 2 ;;
esac
