#pragma once

#include <stdlib.h>
#include <string>
#include <iostream>

//#define DEBUGG_INFO
#define BUFFER_SIZE 200

using namespace std;

/**
 * @brief Finds next port from port range, restart = true for use on every new range
 * @param ports The port range to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_range(string ports, bool restart);

/**
 * @brief Finds next port from port list, restart = true for use on every new list
 * @param ports The port list to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_list(string ports, bool restart);

/**
 * @brief Returns the solo port as an integer, works similarly as next_in_range and next_in_list
 * @param ports One port number
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_solo(string ports, bool restart);
