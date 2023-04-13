from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String)
    trainings = relationship("UserTraining", back_populates="user")

class Training(Base):
    __tablename__ = 'trainings'
    training_id = Column(Integer, primary_key=True)
    training_name = Column(String)
    users = relationship("UserTraining", back_populates="training")

class UserTraining(Base):
    __tablename__ = 'user_trainings'
    user_training_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    training_id = Column(Integer, ForeignKey('trainings.training_id'))
    completion_date = Column(Date)
    user = relationship("User", back_populates="trainings")
    training = relationship("Training", back_populates="users")
