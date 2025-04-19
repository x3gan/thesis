from enum import Enum


class State( Enum ):
    DOWN     = 'DOWN'
    INIT     = 'INIT'
    TWOWAY   = 'TWOWAY'
    EXSTART  = 'EXSTART'
    EXCHANGE = 'EXCHANGE'
    LOADING  = 'LOADING'
    FULL     = 'FULL'