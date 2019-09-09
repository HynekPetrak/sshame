import os
import sys
import uuid
import datetime
from sqlalchemy import (Column, ForeignKey, Integer, String,
        DateTime, Index, Unicode, LargeBinary, Boolean, ForeignKeyConstraint)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, column_property
from sqlalchemy.sql import func
from sqlalchemy import create_engine

Base = declarative_base()

class Host(Base):
    __tablename__ = 'hosts'
    # Here we define columns for the table person
    # Notice that each column is also a normal Python instance attribute.
    #id = Column(Integer, primary_key=True)
    # IP v4 or v6
    address = Column(String(39), primary_key=True)
    port = Column(Integer, primary_key=True)
    dn = Column(String())
    enabled = Column(Boolean, default=True)
    #created = Column(DateTime, default=datetime.datetime.utcnow)
    created = Column(DateTime(timezone=True), server_default=func.now())
    updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    keys = relationship("Credential", back_populates="host")
    commands = relationship("Command", back_populates="host")

class Key(Base):
    __tablename__ = 'keys'
    #id = Column(Integer, primary_key=True)
    fingerprint = Column(String(50), primary_key=True)
    source = Column(Unicode(), nullable=False)
    key_type = Column(String(4), nullable=False)
    private_key = Column(String(), nullable=False)
    enabled = Column(Boolean, default=True)
    created = Column(DateTime(timezone=True), server_default=func.now())
    updated = Column(DateTime(timezone=True), onupdate=func.now())
    hosts = relationship("Credential", back_populates="key")

class Credential(Base):
    __tablename__ = 'credentials'
    #id = Column(Integer, primary_key=True)
    host_address = Column(Integer, primary_key=True)
    host_port = Column(Integer, primary_key=True)
    key_fingerprint = Column(Integer, ForeignKey('keys.fingerprint'), primary_key=True)
    username = Column(String(50), primary_key=True)
    valid = Column(Boolean)
    updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    host = relationship("Host", back_populates="keys")
    key = relationship("Key", back_populates="hosts")
    __table_args__ = (ForeignKeyConstraint([host_address, host_port],
                                           [Host.address, Host.port]),
                      {})

class Option(Base):
    __tablename__ = 'options'
    name = Column(String(), primary_key=True)
    value = Column(String(), nullable=False)
    description = Column(String())

def get_uuid():
    return str(uuid.uuid4())

class Command(Base):
    __tablename__ = 'commands'
    #id = Column(Integer, primary_key=True)
    host_address = Column(Integer, primary_key=True)
    host_port = Column(Integer, primary_key=True)
    cmd = Column(Unicode(), primary_key=True)
    username = Column(String(50), primary_key=True)
    exit_status = Column(Integer)
    stdout = Column(Unicode())
    stderr = Column(Unicode())
    pipe_exit_status = Column(Integer)
    pipe_stdout = Column(Unicode())
    pipe_stderr = Column(Unicode())
    exception = Column(Unicode())
    guid = column_property(username+"@"+host_address+":"+host_port+"#"+cmd)
    updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    host = relationship("Host", back_populates="commands")
    __table_args__ = (ForeignKeyConstraint([host_address, host_port],
                                           [Host.address, Host.port]), {})

class CommandAlias(Base):
    __tablename__ = 'command_aliases'
    alias = Column(Unicode(), primary_key=True)
    cmd = Column(Unicode())
    pipe_to = Column(Unicode())
    enabled = Column(Boolean, default=True)
    updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

#class Address(Base):
#    __tablename__ = 'address'
#    # Here we define columns for the table address.
#    # Notice that each column is also a normal Python instance attribute.
#    id = Column(Integer, primary_key=True)
#    street_name = Column(String(250))
#    street_number = Column(String(250))
#    post_code = Column(String(250), nullable=False)
#    person_id = Column(Integer, ForeignKey('person.id'))
#    person = relationship(Person)

# Create an engine that stores data in the local directory's
# sqlalchemy_example.db file.
#engine = create_engine('sqlite:///session.db')

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
#Base.metadata.create_all(engine)
