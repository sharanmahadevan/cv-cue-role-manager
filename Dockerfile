# CV-CUE role manager
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    DB_PATH=/data/role-manager.db
COPY --from=build /install /usr/local
RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data
EXPOSE 8080
# Fly mounts the volume at /data owned by root: fix ownership, then drop privileges.
CMD ["sh", "-c", "chown app:app /data && exec setpriv --reuid=app --regid=app --init-groups cv-cue-role-manager"]
