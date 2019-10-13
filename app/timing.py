import schedule
import time
from app import db
from app.models import User,recircle_user


def job():
    for user in User.query.all():
    	user.set_count()
    db.commit()
    for re_user in recircle_user:
    	if re_user.rest_day <=0:
    		db.delete(re_user)
    		continue
    	re_user.rest_day -=1
    db.commit()

schedule.every().day.at('00:00').do(job)
def start():
    while True:
        schedule.run_pending()
        time.sleep(1)