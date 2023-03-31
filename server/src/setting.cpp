// setting.cpp: implementation of the setting class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "setting.h"
#include <iostream>
#include <shlwapi.h>

const DWORD buf_len = 2048;

static std::string GetCurrentDirectory()
{
    char path[MAX_PATH];
    path[::GetCurrentDirectory(MAX_PATH, path) ] = 0;
    return path;
}

//////////////////////////////////////////////////////////////////////
setting::setting(const std::string &filename)
{
    std::string filepath;
    if(::PathIsRelative(filename.c_str()) )
        filepath = GetCurrentDirectory() + "\\" + filename;
    else
        filepath = filename;

    char section_buf[buf_len];
    char item_buf[buf_len];
    char *section_ptr = section_buf;
    char *item_ptr;
    std::string key;
    std::string item;
    std::string val;
    DWORD len = ::GetPrivateProfileSectionNames( section_buf, buf_len, filepath.c_str() );
    while ( *section_ptr != '\0' )
    {
        len = ::GetPrivateProfileSection( section_ptr, item_buf, buf_len, filepath.c_str() );
        m_sections.insert(section_ptr);
        item_ptr = item_buf;
        while ( *item_ptr != '\0' )
        {
            key = section_ptr;
            item = item_ptr;
            std::string::size_type pos = item.find('=');
            key.append(item, 0, pos);
            val.assign(item, pos + 1, item.size() - pos);
            m_key2vals.insert( std::pair<std::string, std::string>(key, val) );
            item_ptr += strlen(item_ptr) + 1;
        }
        section_ptr += strlen(section_ptr) + 1;
    }
}

//////////////////////////////////////////////////////////////////////
std::string setting::get_string(const std::string &section, const std::string &entry, const std::string &default_str )
{
    std::map<std::string, std::string>::iterator it = m_key2vals.find(section + entry);
    if( it == m_key2vals.end() || it->second.empty() )
    {
        return default_str;
    }
    else
    {
        return it->second;
    }
}

void setting::set_string(const std::string &section, const std::string &entry, const std::string &value)
{
    if(!value.empty())
    {
        m_key2vals[section + entry] = value;
    }
}

long setting::get_long(const std::string &section, const std::string &entry, long default_int )
{
    std::map<std::string, std::string>::iterator it = m_key2vals.find(section + entry);
    if( it == m_key2vals.end() )
    {
        return default_int;
    }
    else
    {
        return atol( (*it).second.c_str() );
    }
}

void setting::set_long(const std::string &section, const std::string &entry, long value )
{
    char out[16];
    _ultoa_s(value, out, sizeof(out), 10);

    m_key2vals[section + entry] = out;
}

bool setting::get_bool(const std::string &section, const std::string &entry, bool default_bool )
{
    std::map<std::string, std::string>::iterator it = m_key2vals.find(section + entry);
    if( it == m_key2vals.end() )
    {
        return default_bool;
    }
    else
    {
        return atol( (*it).second.c_str() ) != 0;
    }
}

void setting::set_bool(const std::string &section, const std::string &entry, bool value)
{
    char out[16];
    _ultoa_s(value, out, sizeof(out), 10);

    m_key2vals[section + entry] = out;
}

bool setting::is_exist(const std::string &section, const std::string &entry)
{
    return m_key2vals.find(section + entry) != m_key2vals.end();
}