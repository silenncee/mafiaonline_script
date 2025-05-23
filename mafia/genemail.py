import requests 
import time 
import random
import string
import json 
import urllib.parse
from typing import List, Dict, Optional 
from mafiaonline.structures.models import ModelUser, ModelServerConfig 
from mafiaonline.mafiaonline import Client 
from secrets import token_hex 
from msgspec.json import decode 
from requests.exceptions import RequestException
import concurrent.futures
from datetime import datetime, timedelta
import re
from bs4 import BeautifulSoup
import os

# Список прокси в формате http://username:password@ip:port
PROXIES = [
    "http://23.237.210.82:80"
    # Добавьте сюда ваши прокси
    # Пример: "http://user:pass@ip:port"
]

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.last_update = None
        self.update_interval = timedelta(minutes=5)
        self.proxies_file = "working_proxies.json"
        self.load_proxies()
    
    def load_proxies(self):
        try:
            if os.path.exists(self.proxies_file):
                with open(self.proxies_file, 'r') as f:
                    data = json.load(f)
                    if datetime.fromisoformat(data['timestamp']) + timedelta(hours=1) > datetime.now():
                        self.proxies = data['proxies']
                        print(f"Загружено {len(self.proxies)} сохраненных прокси")
                        return
        except Exception as e:
            print(f"Ошибка при загрузке сохраненных прокси: {str(e)}")
    
    def save_proxies(self):
        try:
            with open(self.proxies_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'proxies': self.proxies
                }, f)
        except Exception as e:
            print(f"Ошибка при сохранении прокси: {str(e)}")
    
    def update_proxies(self):
        if (self.last_update and datetime.now() - self.last_update < self.update_interval and 
            len(self.proxies) > 0):
            return

        print("Обновляем список прокси...")
        new_proxies = []
        
        # Получаем прокси из нескольких источников
        try:
            # FreeProxyList
            try:
                response = requests.get('https://free-proxy-list.net/', timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for row in soup.find_all('tr')[1:]:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip = cols[0].text.strip()
                            port = cols[1].text.strip()
                            if ip and port:
                                new_proxies.append(f"http://{ip}:{port}")
            except Exception as e:
                print(f"Ошибка при получении прокси с FreeProxyList: {str(e)}")

            # ProxyScrape
            try:
                response = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all', timeout=10)
                if response.status_code == 200:
                    for proxy in response.text.split('\n'):
                        if proxy.strip():
                            new_proxies.append(f"http://{proxy.strip()}")
            except Exception as e:
                print(f"Ошибка при получении прокси с ProxyScrape: {str(e)}")

            # Geonode
            try:
                response = requests.get('https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps', timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            new_proxies.append(f"http://{ip}:{port}")
            except Exception as e:
                print(f"Ошибка при получении прокси с Geonode: {str(e)}")

            # SpysOne
            try:
                response = requests.get('https://spys.one/free-proxy-list/ALL/', timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for row in soup.find_all('tr', {'class': 'spy1x'}):
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip_port = cols[0].text.strip()
                            if ':' in ip_port:
                                new_proxies.append(f"http://{ip_port}")
            except Exception as e:
                print(f"Ошибка при получении прокси с SpysOne: {str(e)}")

            # HideMyName
            try:
                response = requests.get('https://hidemy.name/en/proxy-list/', timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for row in soup.find_all('tr')[1:]:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip = cols[0].text.strip()
                            port = cols[1].text.strip()
                            if ip and port:
                                new_proxies.append(f"http://{ip}:{port}")
            except Exception as e:
                print(f"Ошибка при получении прокси с HideMyName: {str(e)}")

        except Exception as e:
            print(f"Общая ошибка при получении списка прокси: {str(e)}")

        # Удаляем дубликаты
        new_proxies = list(set(new_proxies))
        print(f"Найдено {len(new_proxies)} уникальных прокси")

        # Проверяем работоспособность прокси
        working_proxies = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_proxy = {
                executor.submit(self.test_proxy, proxy): proxy 
                for proxy in new_proxies
            }
            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    if future.result():
                        working_proxies.append(proxy)
                        print(f"Найден рабочий прокси: {proxy}")
                except Exception:
                    pass

        if working_proxies:
            self.proxies = working_proxies
            self.last_update = datetime.now()
            print(f"Найдено {len(working_proxies)} рабочих прокси")
            self.save_proxies()  # Сохраняем рабочие прокси
        else:
            print("Не удалось найти рабочие прокси")
            # Если не нашли прокси, ждем немного и пробуем снова
            time.sleep(30)
            self.update_proxies()
    
    def test_proxy(self, proxy: str) -> bool:
        try:
            proxies = {
                "http": proxy,
                "https": proxy
            }
            # Пробуем несколько эндпоинтов
            test_urls = [
                'https://api.mafia.dottap.com/',
                'https://www.google.com',
                'https://www.cloudflare.com'
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(
                        url,
                        proxies=proxies,
                        timeout=5,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                        }
                    )
                    if response.status_code == 200:
                        # Дополнительная проверка скорости
                        if response.elapsed.total_seconds() < 3:
                            return True
                except:
                    continue
            return False
        except:
            return False
    
    def get_next_proxy(self) -> Optional[Dict]:
        if not self.proxies:
            self.update_proxies()
            if not self.proxies:
                return None
            
        start_index = self.current_index
        while True:
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            
            if proxy not in self.failed_proxies:
                return {
                    "http": proxy,
                    "https": proxy
                }
            
            if self.current_index == start_index:
                # Все прокси были использованы, обновляем список
                self.update_proxies()
                if not self.proxies:
                    return None
                self.failed_proxies.clear()
                return {
                    "http": self.proxies[0],
                    "https": self.proxies[0]
                }
    
    def mark_proxy_failed(self, proxy: str):
        self.failed_proxies.add(proxy)
        if len(self.failed_proxies) > len(self.proxies) * 0.5:  # Уменьшаем порог до 50%
            self.update_proxies()  # Обновляем список

class UClient(Client): 
    def __init__(self, proxy_manager: Optional[ProxyManager] = None):
        super().__init__()
        self.rest_address = "https://api.mafia.dottap.com"
        self.proxy_manager = proxy_manager
        self.current_proxy = None

    def create_account(self, email: str, password: str, language: str = 'RUS') -> Dict:  
        while True:
            try:
                if self.proxy_manager:
                    self.current_proxy = self.proxy_manager.get_next_proxy()
                
                data = {
                    'email': email,
                    'username': '',
                    'password': self.md5hash.md5Salt(password),
                    'deviceId': token_hex(10),
                    'lang': language,
                    'platform': 'android',
                    'version': '1.14.0'
                }
                
                response: requests.Response = requests.post( 
                    proxies=self.current_proxy, 
                    url=f'{self.rest_address}/user/sign_up', 
                    headers={ 
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept-Encoding": "gzip", 
                        "User-Agent": "okhttp/3.12.0",
                        "Connection": "keep-alive",
                        "Accept": "*/*",
                        "X-Unity-Version": "2021.3.11f1"
                    }, 
                    data=data,
                    timeout=30,
                    verify=True
                ) 
                
                if response.status_code == 400:
                    print(f"Ответ сервера: {response.text}")
                    try:
                        resp_json = response.json()
                        if resp_json.get("error") == "TOO_MANY_REQUESTS":
                            if self.proxy_manager and self.current_proxy:
                                print(f"Меняем прокси из-за ограничения запросов...")
                                self.proxy_manager.mark_proxy_failed(self.current_proxy["http"])
                                continue
                            else:
                                wait_time = int(resp_json.get("data", 60))
                                print(f"Сервер просит подождать {wait_time} секунд...")
                                time.sleep(wait_time + 2)
                                continue
                    except Exception:
                        pass
                
                response.raise_for_status()
                return response.json() 
            except Exception as e:
                print(f"Ошибка при создании аккаунта: {str(e)}")
                if self.proxy_manager and self.current_proxy:
                    print("Пробуем следующий прокси...")
                    self.proxy_manager.mark_proxy_failed(self.current_proxy["http"])
                    continue
                return {"o": False, "error": str(e)}

    def sign_in_new_account(self, email: str, password: str, nickname: str, server_lang: str = 'ru') -> bool: 
        try:
            data = { 
                "d": token_hex(10), 
                "ty": "sin",
                "e": email,
                "pw": self.md5hash.md5Salt(password)
            } 
            self.send_server(data) 

            time.sleep(1)  # Увеличил время ожидания

            data = self._get_data("usi") 
            if not data or data.get("ty") != "usi":
                print("Ошибка при получении данных пользователя")
                return False

            data["uu"]["slc"] = "ru" 

            self.user = decode(json.dumps(data["uu"]), type=ModelUser) 
            self.server_config = decode(json.dumps(data["scfg"]), type=ModelServerConfig) 
            self.token = self.user.token 
            self.id = self.user.user_id 

            self.uns(nickname) 
            self.select_language(server_lang) 
            
            return True
        except Exception as e:
            print(f"Ошибка при входе в аккаунт: {str(e)}")
            return False

class Email:
    def __init__(self) -> None: 
        self.email: str = ""
        self.session = requests.Session()
        self.max_retries = 3
        self.email = self.gen_email()
        print(f"Сгенерирован email: {self.email}")

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        for attempt in range(self.max_retries):
            try:
                response = method(url, **kwargs)
                response.raise_for_status()
                return response
            except RequestException as e:
                if attempt == self.max_retries - 1:
                    raise
                print(f"Попытка {attempt + 1} не удалась: {str(e)}")
                time.sleep(2 ** attempt)

    def gen_email(self) -> str: 
        url: str = 'https://www.emailnator.com/generate-email' 
        
        self._make_request(self.session.get, url)
        token: str = f"{self.session.cookies['XSRF-TOKEN'][:-3]}=" 

        response = self._make_request(
            self.session.post,
            url, 
            headers={ 
                'Content-Type': 'application/json', 
                'X-Requested-With': 'XMLHttpRequest', 
                'X-XSRF-TOKEN': token 
            }, 
            json={"email": ["plusGmail"]}  # Изменено на plusGmail для генерации email с + вместо точек
        ) 

        email = response.json()['email'][0]
        # Убираем точки из email, оставляя только одну перед @
        parts = email.split('@')
        clean_local = parts[0].replace('.', '')
        return f"{clean_local}@{parts[1]}"

    def get_messages(self) -> List[Dict]: 
        url: str = 'https://www.emailnator.com/message-list' 
        
        # Получаем новый токен для каждого запроса
        self._make_request(self.session.get, url)
        token: str = f"{self.session.cookies['XSRF-TOKEN'][:-3]}=" 

        response = self._make_request(
            self.session.post,
            url, 
            headers={ 
                'Content-Type': 'application/json', 
                'X-Requested-With': 'XMLHttpRequest', 
                'X-XSRF-TOKEN': token 
            }, 
            json={"email": self.email} 
        ) 
        
        return response.json().get('messageData', [])
     
    def get_message(self, message_id: str) -> str: 
        url: str = 'https://www.emailnator.com/message-list' 
        
        self._make_request(self.session.get, url)
        token: str = f"{self.session.cookies['XSRF-TOKEN'][:-3]}=" 

        response = self._make_request(
            self.session.post,
            url, 
            headers={ 
                'Content-Type': 'application/json', 
                'X-Requested-With': 'XMLHttpRequest', 
                'X-XSRF-TOKEN': token 
            }, 
            json={ 
                "email": self.email, 
                "messageID": message_id 
            } 
        ) 

        return response.text 

def verify_email(html: str) -> bool: 
    try:
        def find_verify_link(html: str) -> str: 
            for line in html.split('\n'): 
                if 'https://mafia.dottap.com/email/verification' in line: 
                    start = line.find('https://mafia.dottap.com/email/verification')
                    end = line.find('"', start)
                    return line[start:end] if end != -1 else line[start:]
            return ""

        verify_link = find_verify_link(html)
        if not verify_link:
            print("Ссылка верификации не найдена")
            return False

        verification_code = verify_link[48:]
        resp = requests.post( 
            url='https://api.mafia.dottap.com/user/email/verification', 
            headers={ 
                'accept-encoding': 'gzip, deflate, br, zstd', 
                'content-type': 'application/x-www-form-urlencoded;charset=UTF-8', 
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36' 
            }, 
            data=f'verificationCode={verification_code}',
            timeout=30
        ) 
        resp.raise_for_status()
        print(f"Результат верификации: {resp.text}")
        return True
    except Exception as e:
        print(f"Ошибка при верификации email: {str(e)}")
        return False

def save_account_data(email: str, nick: str, password: str):
    accounts_file = "accounts.json"
    try:
        # Загружаем существующие данные
        if os.path.exists(accounts_file):
            with open(accounts_file, 'r', encoding='utf-8') as f:
                accounts = json.load(f)
        else:
            accounts = []

        # Добавляем новый аккаунт
        account_data = {
            "email": email,
            "nickname": nick,
            "password": password,
            "created_at": datetime.now().isoformat()
        }
        accounts.append(account_data)

        # Сохраняем обновленные данные
        with open(accounts_file, 'w', encoding='utf-8') as f:
            json.dump(accounts, f, ensure_ascii=False, indent=2)
            
        print(f"💾 Данные сохранены в {accounts_file}")
    except Exception as e:
        print(f"❌ Ошибка сохранения данных: {str(e)}")

def generate_unique_nick():
    # Список коротких префиксов
    prefixes = ['x', 'z', 'q', 'v', 'w', 'y', 'j', 'k']
    # Список коротких суффиксов
    suffixes = ['a', 'e', 'i', 'o', 'u']
    # Список цифр
    numbers = ['1', '2', '3', '4', '5']
    
    # Генерируем случайный ник
    prefix = random.choice(prefixes)
    suffix = random.choice(suffixes)
    number = random.choice(numbers)
    
    return f"{prefix}{suffix}{number}"

def create_single_account(proxy_manager: Optional[ProxyManager] = None):
    try:
        print("\n1. Генерация email...", end='\r')
        email = Email()
        client = UClient(proxy_manager)

        # Генерируем короткий ник
        nick = generate_unique_nick()
        password = "vvvvvviiiii"

        print(f"\n2. Создание аккаунта: {nick}", end='\r')

        print("3. Отправка запроса на создание аккаунта...", end='\r')
        try:
            result = client.create_account(email=email.email, password=password)
            if not result:
                print("❌ Ошибка: Нет ответа от сервера")
                return False

            if not result.get("o", False):
                error_msg = result.get("error", "Неизвестная ошибка")
                print(f"❌ Ошибка: {error_msg}")
                if "TOO_MANY_REQUESTS" in error_msg:
                    wait_time = int(result.get("data", 60))
                    print(f"⏳ Ожидание {wait_time}с...", end='\r')
                    time.sleep(wait_time + 2)
                return False

            print("✅ Аккаунт создан", end='\r')
        except Exception as e:
            print(f"❌ Ошибка запроса: {str(e)}")
            return False

        print("4. Вход в аккаунт...", end='\r')
        try:
            if not client.sign_in_new_account(email=email.email, password=password, nickname=nick):
                print("❌ Ошибка входа")
                return False
            print("✅ Вход выполнен", end='\r')
        except Exception as e:
            print(f"❌ Ошибка входа: {str(e)}")
            return False

        print("5. Ожидание верификации...", end='\r')
        max_attempts = 20
        attempt = 0
        while attempt < max_attempts:
            try:
                messages = email.get_messages()
                if not messages:
                    if attempt % 5 == 0:
                        print(f"⏳ Ожидание... {attempt + 1}/{max_attempts}", end='\r')
                    attempt += 1
                    time.sleep(1)
                    continue

                for msg in messages:
                    if msg['from'] == '"Мафия Онлайн" <mafia@mail.dottap.com>':
                        print("6. Верификация...", end='\r')
                        message_content = email.get_message(msg['messageID'])
                        if verify_email(message_content):
                            print("\n✅ Аккаунт создан и верифицирован")
                            print(f"📧 {email.email}")
                            print(f"👤 {nick}")
                            print(f"🔑 {password}")
                            
                            # Сохраняем данные аккаунта
                            save_account_data(email.email, nick, password)
                            
                            return True
                        else:
                            print("❌ Ошибка верификации")
                            return False

                attempt += 1
                time.sleep(1)
            except Exception as e:
                print(f"❌ Ошибка проверки: {str(e)}")
                time.sleep(1)

        print("❌ Таймаут верификации")
        return False
    except Exception as e:
        print(f"❌ Ошибка: {str(e)}")
        return False

def main():
    proxy_manager = ProxyManager()
    account_counter = 0
    
    print("🚀 Запуск регистрации аккаунтов...")
    print("=" * 40)
    
    while True:
        try:
            if create_single_account(proxy_manager):
                account_counter += 1
                print(f"\n✅ Создано: {account_counter}")
                delay = random.uniform(3, 5)  # Уменьшаем задержку
                time.sleep(delay)
            else:
                time.sleep(3)  # Уменьшаем время ожидания при ошибке

        except KeyboardInterrupt:
            print(f"\n🛑 Остановлено. Создано: {account_counter}")
            break
        except Exception as e:
            print(f"❌ Ошибка: {str(e)}")
            time.sleep(3)

if __name__ == "__main__":
    main()