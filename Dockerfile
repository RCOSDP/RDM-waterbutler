# Build stage: compilers and development headers are only needed to install
# the Python dependencies, so they stay out of the runtime image.
FROM python:3.13-slim AS build

ENV POETRY_HOME=/opt/poetry \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=0 \
    POETRY_VIRTUALENVS_IN_PROJECT=1
ENV PATH="${POETRY_HOME}/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y \
        git \
        libevent-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        # cryptography
        build-essential \
        libssl-dev \
        libffi-dev \
    && apt-get clean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Keep poetry in its own virtualenv so it is not installed into site-packages
RUN python -m venv ${POETRY_HOME} \
    && ${POETRY_HOME}/bin/pip install --no-cache-dir poetry==2.1.2 \
    && pip install --no-cache-dir setuptools==80.1.0

RUN mkdir -p /code
WORKDIR /code

COPY pyproject.toml poetry.lock /code/
RUN poetry install --no-root --without=docs

# Copy the rest of the code over
COPY ./ /code/

RUN poetry install --without docs


# Runtime stage
FROM python:3.13-slim

RUN usermod -d /home www-data && chown www-data:www-data /home

RUN apt-get update \
    && apt-get install -y \
        # grab gosu for easy step-down from root
        gosu \
    && apt-get clean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /code /code

# pip is not needed at runtime and ships its own copies of urllib3, msgpack and
# setuptools, so remove it together with the wheel bundled for ensurepip
RUN python3 -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip/_bundled \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13

WORKDIR /code

ARG GIT_COMMIT=
ENV GIT_COMMIT=${GIT_COMMIT}

EXPOSE 7777

CMD ["gosu", "www-data", "python3", "-m", "invoke", "server"]
