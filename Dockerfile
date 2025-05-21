FROM python:3

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
RUN pip install gunicorn flask

ENV SECRET_KEY="d3b07384d113edec49eaa6238ad5ff00c1f1d4a5d9f3b3f9a3c9c5e8f2b2b2b"
ENV FLASK_ENV=production

COPY . /app

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]