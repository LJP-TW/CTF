FROM python:3.7.3

RUN mkdir -p /usr/src/app
RUN mkdir /usr/src/app/data
RUN useradd appuser
RUN chown appuser:appuser /usr/src/app/data

WORKDIR /usr/src/app
COPY . .

RUN pip install -r requirements.txt
RUN pip install pyopenssl
RUN python app.py init
RUN chown appuser:appuser data/database.db

EXPOSE 5000

USER appuser:appuser
CMD ["python", "app.py", "run"]

