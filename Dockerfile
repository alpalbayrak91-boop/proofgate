FROM python:3.11-slim

WORKDIR /action
COPY . /action
RUN pip install --no-cache-dir --no-deps -e .

ENTRYPOINT ["python3", "-m", "proofgate.action_runner"]
