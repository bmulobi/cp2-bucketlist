import os

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager  # class for handling a set of commands

from app import db, create_app

app = create_app(config_name=os.getenv("APP_SETTINGS"))
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command("db", MigrateCommand)

@manager.command
def create_db(dbname):
    """Creates database with tables"""

    os.system('createdb ' + dbname)
    db.create_all()
    db.session.commit()


@manager.command
def drop_db(dbname):
    """Deletes database"""
    os.system('dropdb ' + dbname)

if __name__ == "__main__":
    manager.run()