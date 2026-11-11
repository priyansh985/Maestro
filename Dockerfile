# Supply an immutable Python 3.13 base, e.g. python:3.13-slim-bookworm@sha256:...
# No default: a floating tag must not silently become a release artifact.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS build
ARG PYTHON_IMAGE
RUN python -c "import os,re,sys; assert sys.version_info[:2] == (3,13); assert re.fullmatch(r'.+@sha256:[0-9a-f]{64}',os.environ['PYTHON_IMAGE'])"
WORKDIR /build
RUN python -m pip install --no-cache-dir uv==0.12.2
COPY pyproject.toml uv.lock setup.py MANIFEST.in README.md LICENSE ./
COPY configs ./configs
COPY src ./src
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt --output-file runtime-requirements.txt \
    && uv build --no-sources --wheel \
    && python -m pip wheel --wheel-dir /wheelhouse --requirement runtime-requirements.txt \
    && cp dist/*.whl /wheelhouse/

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 MAESTRO_PROFILE=research
COPY --from=build /wheelhouse /wheelhouse
RUN python -m pip install --no-index --find-links=/wheelhouse maestro-secure-agentic-ai \
    && rm -rf /wheelhouse \
    && useradd --create-home --uid 10001 maestro
WORKDIR /app
RUN chown maestro:maestro /app
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "maestro.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
