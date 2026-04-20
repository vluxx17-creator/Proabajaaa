import discord
from discord.ext import commands
import os
import sqlite3
import datetime
import io
import re
import requests
from dotenv import load_dotenv
from flask import Flask
from threading import Thread

# --- Инициализация переменных ---
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
ADMIN_ID = os.getenv('ADMIN_ID')
VK_TOKEN = os.getenv('VK_TOKEN')

if ADMIN_ID:
    ADMIN_ID = int(ADMIN_ID)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# --- База данных ---
db = sqlite3.connect('osint_system.db')
cursor = db.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users 
               (user_id INTEGER PRIMARY KEY, sub_until TEXT, requests_today INTEGER, last_req_date TEXT)''')
db.commit()

# --- Веб-сервер для Render ---
app = Flask('')
@app.route('/')
def home(): return "System Status: Online"

def run():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

def keep_alive():
    t = Thread(target=run)
    t.daemon = True
    t.start()

# --- Генераторы огромных отчетов ---

def get_ip_report(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719").json()
        if res.get('status') == 'fail': return f"❌ Ошибка API: {res.get('message')}"
        
        now = datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        report = f"""
╔════════════════════════════════════════════════════════════╗
  ДЕТАЛИЗИРОВАННЫЙ OSINT-ОТЧЕТ ПО СЕТЕВОМУ АДРЕСУ (IPv4)
╚════════════════════════════════════════════════════════════╝
  Дата генерации: {now}
  Цель: {ip}
  Статус сканирования: ЗАВЕРШЕНО (100%)

  [ СЛОЙ 1: ГЕОЛОКАЦИОННЫЕ ДАННЫЕ ]
  ------------------------------------------------------------
  ● Страна:          {res.get('country', 'Н/Д')} ({res.get('countryCode', '??')})
  ● Регион/Область:  {res.get('regionName', 'Н/Д')}
  ● Город:           {res.get('city', 'Н/Д')}
  ● Почтовый индекс: {res.get('zip', 'Н/Д')}
  ● Широта:          {res.get('lat', 'Н/Д')}
  ● Долгота:         {res.get('lon', 'Н/Д')}
  ● Часовой пояс:    {res.get('timezone', 'Н/Д')}

  [ СЛОЙ 2: ИНФОРМАЦИЯ О ПРОВАЙДЕРЕ И СЕТИ ]
  ------------------------------------------------------------
  ● ISP (Провайдер): {res.get('isp', 'Н/Д')}
  ● Организация:     {res.get('org', 'Н/Д')}
  ● AS (Автономка):  {res.get('as', 'Н/Д')}
  ● Реверс DNS:      {res.get('reverse', 'Н/Д')}

  [ СЛОЙ 3: АНАЛИЗ УГРОЗ И ТИПА СОЕДИНЕНИЯ ]
  ------------------------------------------------------------
  ● Использование Proxy:     {'[!] ОБНАРУЖЕНО' if res.get('proxy') else '[ ] Чисто'}
  ● VPN Соединение:          {'[!] ОБНАРУЖЕНО' if res.get('proxy') else '[ ] Не выявлено'}
  ● Мобильная сеть (3G/4G):  {'[+] Да' if res.get('mobile') else '[ ] Нет'}
  ● Хостинг/Дата-центр:      {'[!] Да' if res.get('hosting') else '[ ] Нет'}

  [ СЛОЙ 4: СИСТЕМНЫЕ ВЫВОДЫ ]
  ------------------------------------------------------------
  Объект находится в {res.get('city')}. Провайдер {res.get('isp')} 
  использует диапазоны адресов {res.get('as')}. 
  Признаков использования средств анонимизации: {'ВЫЯВЛЕНО' if res.get('proxy') else 'НЕ ВЫЯВЛЕНО'}.

══════════════════════════════════════════════════════════════
          Сгенерировано через SearchHems Discord Bot
══════════════════════════════════════════════════════════════
"""
        return report
    except: return "Критическая ошибка при генерации IP-отчета."

def get_vk_report(target):
    user_id = target.split('/')[-1] if '/' in target else target
    try:
        params = {
            "user_ids": user_id, 
            "fields": "bdate,city,counters,last_seen,verified,followers_count,status,connections,site,relation", 
            "access_token": VK_TOKEN, 
            "v": "5.131"
        }
        res = requests.get("https://api.vk.com/method/users.get", params=params).json()
        if 'error' in res: return f"❌ Ошибка VK API: {res['error']['error_msg']}"
        
        d = res['response'][0]
        now = datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        ls_text = datetime.datetime.fromtimestamp(d['last_seen']['time']).strftime('%d.%m.%Y %H:%M:%S') if 'last_seen' in d else "Скрыто"
        
        report = f"""
╔════════════════════════════════════════════════════════════╗
  ГЛУБОКИЙ OSINT-АНАЛИЗ ПРОФИЛЯ СОЦИАЛЬНОЙ СЕТИ (VK)
╚════════════════════════════════════════════════════════════╝
  Дата генерации: {now}
  Объект: https://vk.com/id{d.get('id')}
  
  [ СЛОЙ 1: ПЕРСОНАЛЬНАЯ ИДЕНТИФИКАЦИЯ ]
  ------------------------------------------------------------
  ● Имя Фамилия:    {d.get('first_name')} {d.get('last_name')}
  ● ID Пользователя: {d.get('id')}
  ● Верификация:    {'[✅] Подтвержден' if d.get('verified') else '[ ] Нет'}
  ● Дата рождения:  {d.get('bdate', 'Скрыто')}
  ● Город:          {d.get('city', {}).get('title', 'Не указан')}
  ● Семейное пол.:  {str(d.get('relation', 'Н/Д'))}
  ● Статус:         "{d.get('status', 'Пусто')}"

  [ СЛОЙ 2: ЦИФРОВОЙ СЛЕД И АКТИВНОСТЬ ]
  ------------------------------------------------------------
  ● Друзей в базе:  {d.get('counters', {}).get('friends', 0)}
  ● Подписчиков:    {d.get('followers_count', 0)}
  ● Фотографий:     {d.get('counters', {}).get('photos', 0)}
  ● Видеозаписей:   {d.get('counters', {}).get('videos', 0)}
  ● Подписок:       {d.get('counters', {}).get('pages', 0)}
  ● Последний вход: {ls_text}

  [ СЛОЙ 3: СВЯЗАННЫЕ АККАУНТЫ И ВНЕШНИЕ ССЫЛКИ ]
  ------------------------------------------------------------
  ● Сайт:           {d.get('site', 'Нет')}
  ● Instagram:      {d.get('instagram', 'Не привязан')}
  ● Skype:          {d.get('skype', 'Не привязан')}
  ● Twitter:        {d.get('twitter', 'Не привязан')}
  ● Facebook:       {d.get('facebook', 'Не привязан')}

  [ СЛОЙ 4: ВЕРДИКТ СИСТЕМЫ ]
  ------------------------------------------------------------
  Профиль {d.get('first_name')} {d.get('last_name')} имеет высокую 
  социальную активность ({d.get('followers_count')} фолловеров). 
  Наличие привязанных соцсетей: {'ЕСТЬ' if d.get('instagram') or d.get('skype') else 'НЕТ'}.
  Рекомендуется проверить базу утечек по найденным никнеймам.

══════════════════════════════════════════════════════════════
          Сгенерировано через SearchHems Discord Bot
══════════════════════════════════════════════════════════════
"""
        return report
    except: return "Критическая ошибка при генерации VK-отчета."

# --- Командный интерфейс ---

@bot.command()
async def search(ctx, *, target: str):
    user_id = ctx.author.id
    today = str(datetime.date.today())
    
    cursor.execute("SELECT sub_until, requests_today, last_req_date FROM users WHERE user_id = ?", (user_id,))
    data = cursor.fetchone()
    
    if not data:
        cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (user_id, "2000-01-01", 0, today))
        db.commit()
        data = ("2000-01-01", 0, today)

    sub_until, req_count, last_date = data
    is_prem = datetime.datetime.strptime(sub_until, '%Y-%m-%d').date() >= datetime.date.today()
    limit = 50 if is_prem else 2

    if last_date != today: req_count = 0
    if req_count >= limit:
        return await ctx.send(f"⚠️ Лимит исчерпан: **{req_count}/{limit}**. Купите подписку через админа.")

    await ctx.send(f"🛡️ **SearchHems V2**: Инициализация поиска для `{target}`...")
    
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', target):
        report = get_ip_report(target)
    else:
        report = get_vk_report(target)

    # Отправка отчета файлом в ЛС
    file = discord.File(io.BytesIO(report.encode('utf-8')), filename=f"OSINT_REPORT_{target}.txt")
    try:
        await ctx.author.send(f"📄 Ваш персональный отчет по цели `{target}` готов:", file=file)
        await ctx.send(f"✅ Отчет успешно сформирован и отправлен в ЛС. (Запрос {req_count + 1}/{limit})")
    except discord.Forbidden:
        await ctx.send("❌ Ошибка: Я не могу отправить вам ЛС. Включите их в настройках конфиденциальности.")

    cursor.execute("UPDATE users SET requests_today = ?, last_req_date = ? WHERE user_id = ?", (req_count + 1, today, user_id))
    db.commit()

@bot.command()
async def add_sub(ctx, member: discord.Member, days: int):
    if ctx.author.id != ADMIN_ID: return
    new_date = str(datetime.date.today() + datetime.timedelta(days=days))
    cursor.execute("UPDATE users SET sub_until = ? WHERE user_id = ?", (new_date, member.id))
    db.commit()
    await ctx.send(f"👑 Пользователю {member.mention} выдана подписка до **{new_date}**")

@bot.event
async def on_ready():
    print(f"[{datetime.datetime.now()}] Бот {bot.user} запущен и готов к поиску.")

keep_alive()
bot.run(TOKEN)
