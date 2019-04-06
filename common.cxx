#include "common.h"


using namespace std;

/**
 * @brief Finds next port from port range, restart = true for use on every new range
 * @param ports The port range to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_range(string ports, bool restart)
{
    static int last_port = -1;
    static int begining;
    static int end;
    int hyphon_ind = ports.find("-");
    size_t index;
    bool error = false;

    if(last_port == -1 || restart)
    {
        string begining_str = ports.substr(0, hyphon_ind);
        try
        {
            begining = stoi(begining_str, &index);
        }
        catch(exception e)
        {
            error = true;
        }

        if(error || begining_str[index] != '\0' || begining < 0)
        {
            cerr << "Wrong begining port number was given: " << begining_str << endl;
            return -2;
        }

        string end_str = ports.substr(hyphon_ind + 1);
        try
        {
            end = stoi(end_str, &index);
        }
        catch(exception e)
        {
            error = true;
        }

        if(error || end_str[index] != '\0' || end < 0)
        {
            cerr << "Wrong end port number was given: " << end_str << endl;
            return -2;
        }

        if(begining > end)
        {
            cerr << "Negative range was given." << endl;
        }

        last_port = begining -1;
    }
    
    last_port++;
    
    if(last_port > end)
        return -1;
    else
        return last_port;
}

/**
 * @brief Finds next port from port list, restart = true for use on every new list
 * @param ports The port list to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_list(string ports, bool restart)
{
    static int last_position;
    bool error = false;
    if(restart)
        last_position = 0;

    if(last_position == -1)
        return -1;

    int next_position = ports.find(',', last_position);

    string port_str = ports.substr(last_position, next_position - last_position);

    last_position = (next_position == string::npos) ? -1 : next_position + 1;
    
    size_t index;
    int port;

    try
    {
        port = stoi(port_str, &index);
    }
    catch(exception e)
    {
        error = true;
    }

    if(error || port_str[index] != '\0' || port < 0)
    {
        cerr << "Wrong port number was given." << endl;
        return -2;
    }

    return port;
}

/**
 * @brief Returns the solo port as an integer, works similarly as next_in_range and next_in_list
 * @param ports One port number
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_solo(string ports, bool restart)
{
    static int last_port = -1;
    size_t index;
    bool error = false;

    if(restart)
        last_port = -1;

    int port;
    try
    {
        port = stoi(ports, &index);
    }
    catch(exception e)
    {
        error = true;
    }

    if(error || ports[index] != '\0' || port < 0)
    {
        cerr << "Wrong port number was given." << endl;
        return -2;
    }

    if(last_port != port)
    {
        last_port = port;
        return port;
    }
    
    return -1;
}
