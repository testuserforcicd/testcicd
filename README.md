# WAF
Web Application Firewall

При первой настройке необходимо ввести:

```
docker-compose up -d
```
Для контейнера web, имя которого можно найти через 

```
docker ps -a
```
Необходимо добавить суперпользователя следующей комнадой:

```
docker-compose exec -it имяконтейнера-web-1 python manage.py createsuperuser
```
Для работы входа через Oauth GitHub необходимо зайти в панель localhost/admin/  -> social applications -> add и добавить client id и secret key.
