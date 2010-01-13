/* 
 * File:   main.cpp
 * Author: nagash
 *
 * Created on 3 gennaio 2010, 12.19
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include <eibnetmux/enmx_lib.h>
#include <iostream>

#define  FALSE          0
#define  TRUE           1



using namespace std;

int main(int argc, char** argv)
{



    // SETUP -------  USING SETUP API: http://eibnetmux.sourceforge.net/userdoc/html/group__xgSetup.html

    int api_version;
    sENMX_Server * serverList;
    sENMX_Server serverConnected;
    ENMX_HANDLE enmx_handle;


    //future variabili di input:
    const char* hostname = "hostname_prova";
    const char* clientId = "DB_master_creator";



    
    api_version = enmx_init();//inizializza la libreria. Nella release corrente non fa nulla.
    serverList = enmx_getservers (5);//raccolgo le informazioni di tutti i server in rete rilevabili in 5 secondi.

    while(serverList != NULL) //scorro tutta la lista alla ricerca dell'host desiderato.
    {
        if(strcmp(serverList->hostname, hostname) == 0 )//se l'host corrente ha lo stesso nome di quello desiderato.
        {
            enmx_handle = enmx_open((char*)hostname, (char*)clientId);//mi connetto all'host desiderato.
            serverConnected = *serverList; //memorizzo le informazioni del server a cui mi sono connesso in una struttura separata.
        }
        else serverList = serverList->next;//se non è l'host desiderato vado avanti a scorrere la lista
    }
    enmx_releaseservers (serverList);//rilascio la lista di server





    
    // BUS ACCESS  ------- USING BUS ACCESS API: http://eibnetmux.sourceforge.net/userdoc/html/group__xgBus.html
    //future variabili di input:
    const char* user = "username";
    const char* password = "passwd";
    ENMX_ADDRESS knxaddrSensore[10];
    ENMX_ADDRESS knxaddrContatore;

    knxaddrContatore = enmx_getaddress("0mmm msss gggg gggg");//cambiare il valore a seconda dell'indirizzo
    knxaddrSensore[0] = enmx_getaddress("0mmm msss gggg gggg");
    
    
    switch( enmx_auth(enmx_handle, (char*)user, (char*)password ) ) //provo a connettermi e gestisco gli errori
    {
        //potrei semplificare la gestione degli errori stampando direttamente enmx_errormessage.
        //Ma uso switch per chiarezza essendo una prova.
        case -1:
        {
            //enmx_auth ritorna un errore di autenticazione con -1
            cout << "errore autenticazione: " << enmx_errormessage(-1) << endl;
        }
        case ENMX_E_NO_CONNECTION:
        {
            //enmx_auth ritorna un errore di connessione (handle invalido)
            cout << "errore di connessione (handle invalido): " << enmx_errormessage(ENMX_E_NO_CONNECTION) << endl;
        }
        default:
        {
            cout << "connessione ed autenticazione effettuata con successo\n";
        }        
    }


    while( true )
    {
        uint16_t len;
        unsigned char* value;

        value = enmx_read(enmx_handle, knxaddrContatore, &len);
        cout << value;
    }

    return 0;
}

