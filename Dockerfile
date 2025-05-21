FROM python:3

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
RUN pip install flask


COPY . /app

CMD ["flask", "--host=0.0.0.0", "--port=5000", "app:app"]