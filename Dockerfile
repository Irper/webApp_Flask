FROM python:3

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
RUN pip install gunicorn flask


COPY . /app

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]