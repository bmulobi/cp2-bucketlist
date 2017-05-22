import os

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager  # class for handling a set of commands

from app import db, create_app
from instance import config

app = create_app(config_name=config.app_config["development"])
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command("db", MigrateCommand)

if __name__ == "__main__":
    manager.run()