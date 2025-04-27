import random
import mafiaonline
import time
from mafiaonline.mafiaonline import Client
from mafiaonline.mafiaonline import Roles
import threading

Mafia = mafiaonline.Client()
Mafia.sign_in("nickname", "password")


def create_and_join_room(room_title):
    try:
        selected_roles = [
            Roles.CIVILIAN,
            Roles.MAFIA,
            Roles.SHERIFF,
            Roles.DOCTOR,
            Roles.JOURNALIST,
            Roles.LOVER,
            #Roles.BODYGUARD,
            #Roles.INFORMER,
            #Roles.TERRORIST,
            Roles.BARMAN,
            Roles.SPY

        ]

        room = Mafia.create_room(title=room_title, selected_roles=selected_roles)
        print(f"Успешно создана комната: {room.title} с ID {room.room_id}")

        Mafia.join_room(room_id=room.room_id, password="123")
        print("Успешно присоединился к комнате.")
    except Exception as e:
        print(f"соединение: {e}")

def spam_rooms(room_title):
    while True:
        create_and_join_room(room_title)
        time.sleep(5)

title = input("Введите название комнаты: ")
spam_thread = threading.Thread(target=spam_rooms, args=(title,))
spam_thread.start()


while True:
    time.sleep(2)  # Задержка для основного цикла
