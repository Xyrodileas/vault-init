ARG TEST_IMAGE
FROM $TEST_IMAGE

COPY requirements.txt /requirements.txt
COPY dev-requirements.txt /dev-requirements.txt

RUN pip install -r /requirements.txt -r /dev-requirements.txt