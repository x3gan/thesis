from enum import Enum


class States( Enum ):
    DOWN     = 'DOWN'
    INIT     = 'INIT'
    TWOWAY   = 'TWOWAY'
    EXSTART  = 'EXSTART'
    EXCHANGE = 'EXCHANGE'
    LOADING  = 'LOADING'
    FULL     = 'FULL'