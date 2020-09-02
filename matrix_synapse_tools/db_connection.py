from sqlalchemy import Column, String, Boolean
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm.exc import NoResultFound



class Group_user(Base):
    __tablename__ = "group_users"

    group_id = Column(String, primary_key=True)
    user_id = Column(String, primary_key=True)
    is_admin = Column(Boolean)
    is_public = Column(Boolean)

    def __repr__(self):
        return "<GroupUser(group_id={}, user_id={}, is_admin={}, is_public={})>".format(
            self.group_id, self.user_id, self.is_admin, self.is_public
        )


class Synapse_db_connection():
    def __init__(self, db_type, user, password, host, db_name, show=False):
        self.engine = create_engine(f"{db_type}://{user}:{password}@{host}/{db_name}",
                                    encoding="utf8",
                                    show=show)
        Base = automap_base()
        Base.prepare(self.engine, reflect=True)
        self.classes = Base.classes
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def make_users_group_admin(self, user_id, group_id):
        Group_user = self.classes.group_users
        query = self.engine.query(Group_user).filter(
            Group_user.user_id == user_id, Group_user.group_id == group_id
        )
        try:
            user = query.one()
        except NoResultFound:
            return
        user.is_admin = True

    def get_active_user_ids(self):
        pass
