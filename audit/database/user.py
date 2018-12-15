from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import hashlib
import uuid

engine = create_engine('sqlite:///resources/db/database.db')
Base = declarative_base()
db_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class User(Base):
    __tablename__ = 'user'

    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(60), nullable=False, unique=True)
    password = Column('password', String(60), nullable=False)

    def __repr__(self):
        return "<User: " + self.name + ">"

    @staticmethod
    def create_user(name, password):
        user = User(name=name, password=hash_password(password))
        session = db_session()
        session.add(user)
        session.commit()
        session.close()

    @staticmethod
    def check_user(name, password):
        session = db_session()
        query = session.query(User).filter_by(name=name)
        result_user = query.first()
        if not check_password(result_user.password, password):
            print("not same")
            result_user = None
        session.close()
        return result_user

    @staticmethod
    def delete_user(name, password):
        user = User.check_user(name, password)
        session = db_session()
        session.delete(user)
        session.commit()
        session.close()


def hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt


def check_password(hashed_password, user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()


def init_db():
    Base.metadata.create_all(bind=engine)
