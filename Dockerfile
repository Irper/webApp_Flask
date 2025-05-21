FROM python:3

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt
RUN pip install waitress flask


COPY . /app

CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "app:app"]