#ifndef __HTTPDOWNLOADER_H__
#define __HTTPDOWNLOADER_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
http://ahttp.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include <frame/AsynFile_internal.h>
#include <frame/AsynNetwork_internal.h>
#include <frame/asm/INet.h>
#include <frame/asm/IProxy.h>
#include "setting.h"
using namespace asynsdk;

class CHttpDownloader : public asyn_message_events_impl
{
public:
    CHttpDownloader(InstancesManager *lpInstanceManager, IAsynFrameThread *lpAsynFrameThread)
      : m_setsfile("proxy.txt"), m_af(AF_INET), m_startpos(0), m_referurl(0), m_nochkcert(true), m_hNotify(::CreateEvent(0, 1, 0, 0))
    {
        m_spInstanceManager = lpInstanceManager;
        m_spAsynFrameThread = lpAsynFrameThread;
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork), IID_IAsynNetwork, (void **)&m_spAsynNetwork);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);
    }
    virtual ~CHttpDownloader()
    {
        CloseHandle(m_hNotify);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CHttpDownloader)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IUnknown **objects );

public:
    const char *Parse(int argc, const char *argv[])
    {
        const char *httpurl = 0;
        for(int i = 1; i < argc; ++ i)
        {
            if( strcmp(argv[i], "/?") == 0 || 
                strcmp(argv[i], "--help") == 0 )
            {
                httpurl = 0;
                break;
            }

            if( argv[i][0] == '-' )
            {
                if( strcmp(argv[i], "-referurl") == 0 )
                {
                    if( argc > ++ i)
                        m_referurl = argv[i];
                    continue;
                }
                if( strcmp(argv[i], "-check-certificate") == 0 )
                {
                    m_nochkcert = false;
                    continue;
                }
                if( strcmp(argv[i], "-4") == 0 )
                {
                    m_af = AF_INET;
                    continue;
                }
                if( strcmp(argv[i], "-6") == 0 )
                {
                    m_af = 23;
                    continue;
                }
                if( strcmp(argv[i], "-c") == 0 )
                {
                    if( argc > ++ i)
                        m_startpos = _atoi64(argv[i]);
                    continue;
                }
                if( strcmp(argv[i], "-s") == 0 )
                {
                    if( argc > ++ i)
                        m_setsfile.set_string("ssl", "algo", argv[i]);
                    continue;
                }
                if( strcmp(argv[i], "-o") == 0 )
                {
                    if( argc > ++ i)
                        m_savename = argv[i];
                    continue;
                }
                if( strcmp(argv[i], "-u") == 0 )
                {
                    if( argc > ++ i)
                    {// protocol://[user:password@]host[:port]/ver?params
                        std::string tmpurl = argv[i];

                        std::string::size_type pos1 = tmpurl.find("://");
                        if( pos1 == std::string::npos )
                        {
                            continue;
                        }

                        std::string schema = tmpurl.substr(0, pos1);
                        _strlwr_s((char*)schema.c_str(), schema.size() + 1);
                        if( schema != "http" &&
                            schema != "socks" ) 
                        {
                            continue;
                        }
                        else
                        {
                            pos1 += 3;
                        }

                        m_setsfile.set_string("proxy", "protocol", schema);

                        std::string::size_type pos2 = tmpurl.find('/', pos1);
                        std::string hostport; //[user:password@]host[:port]

                        if( pos2 == std::string::npos )
                        {
                            hostport = tmpurl.substr(pos1);
                        }
                        else
                        {// ver?method=v&ssl=v
                            hostport = tmpurl.substr(pos1, pos2 - pos1);

                            pos2 += 1;
                            std::string::size_type post = tmpurl.find_first_of("?=", pos2);
                            if( post == std::string::npos )
                            {
                                m_setsfile.set_string("proxy", "version", tmpurl.substr(pos2));
                            }
                            else
                            {
                                std::string params;
                                if( tmpurl[post] != '?' )
                                {
                                    params = tmpurl.substr(pos2);
                                }
                                else
                                {
                                    params = tmpurl.substr(post + 1);
                                    m_setsfile.set_string("proxy", "version", tmpurl.substr(pos2, post - pos2));
                                }

                                std::map<std::string, std::string> t;
                                const char *s = params.c_str(), *e = s + params.size(), *i;
                                do{
                                    i = strchr(s, '=');
                                    if(!i ) break;

                                    std::string key(s, i - s);

                                    s = i + 1; //skip '='

                                    i = strchr(s, '&');

                                    t[key] = std::string(s, i? (i - s) : (e - s));

                                    if(!i ) break;

                                    s = i + 1; //skip '&'
                                }while(1);

                                m_setsfile.set_string("proxy", "method", t["method"]);
                                m_setsfile.set_string("proxy", "ssl", t["ssl"]);
                            }
                        }

                        std::string::size_type pos3 = hostport.find('@');
                        if( pos3 != std::string::npos )
                        {
                            std::string account = hostport.substr(0, pos3);
                            hostport.erase(0, pos3 + 1);

                            std::string::size_type post = account.find(':');
                            if( post == std::string::npos )
                            {
                                m_setsfile.set_string("proxy", "user", account);
                            }
                            else
                            {
                                m_setsfile.set_string("proxy", "user", account.substr(0, post));
                                m_setsfile.set_string("proxy", "password", account.substr(post + 1));
                            }
                        }

                        std::string::size_type pos4 = hostport.find(':');
                        if( pos4 == std::string::npos )
                        {
                            m_setsfile.set_string("proxy", "host", hostport);
                        }
                        else
                        {
                            m_setsfile.set_string("proxy", "host", hostport.substr(0,  pos4));
                            m_setsfile.set_string("proxy", "port", hostport.substr(pos4 + 1));
                        }
                    }
                    continue;
                }
            }
            else
            {
                std::string tmpurl = argv[i];

                std::string::size_type pos1 = tmpurl.find("://");
                if( pos1 == std::string::npos )
                {
                    continue;
                }
                else
                {
                    httpurl = argv[i];
                }
            }
        }
        return httpurl;
    }

    bool Start(std::string url)
    {// url格式， protocol://[user:password@]host[:port]/path/[;parameters][?query]#fragment
        m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (void **)&m_spSpeedController);
 
        std::string::size_type pos1 = url.find("://");
        if( pos1 == std::string::npos )
        {
            printf("fail to parse %s\n", url.c_str());
            return false;
        }

        std::string schema = url.substr(0, pos1);
        _strlwr_s((char*)schema.c_str(), schema.size()+1);

        {// skip ://
            pos1 += 3;
        }
 
        std::string::size_type pos2 = url.find('/', pos1);

        std::string hostport;
        if( pos2 == std::string::npos )
        {
            hostport = url.substr(pos1);
            m_filepath = "/";
        }
        else
        {
            hostport = url.substr(pos1, pos2 - pos1);

            std::string::size_type pos3 = url.find_first_of(";?#", pos2 + 1);
            m_filepath = pos3 == std::string::npos? url.substr(pos2) : url.substr(pos2, pos3 - pos2);
            std::string::size_type pos4 = m_filepath.rfind('/');
            m_filename = m_filepath.substr(pos4 + 1);
        }

        if( m_filename.empty()) 
            m_filename = "index.html";

        std::string::size_type pos3 = hostport.find('@');
        if( pos3 != std::string::npos )
        {
            hostport.erase(0, pos3 + 1);
        }

        std::string::size_type pos4 = hostport.find(':');
        if( pos4 == std::string::npos )
        {
            m_host = hostport;
            m_port = 80;
            if( schema == "https") m_port = 443;
            if( schema == "ftp"  ) m_port = 21;
            if( schema == "ftps" ) m_port = 21; //显式over TLS
        }
        else
        {
            m_host = hostport.substr(0, pos4);
            m_port = (PORT)atoi(hostport.substr(pos4 + 1).c_str());
        }

        if( m_savename.empty())
            m_savename = m_filename;

        std::string proxyname = m_setsfile.get_string("proxy", "protocol", "none");
        if( proxyname != "none" &&
            proxyname != "http" &&
            proxyname != "socks" )
        {
            printf("can't support %s-proxy\n", proxyname.c_str());
            return false;
        }

        CComPtr<IAsynTcpSocket> spAsynInnSocket;
        m_spAsynNetwork->CreateAsynTcpSocket(&spAsynInnSocket );

        CComPtr<IAsynRawSocket> spAsynPtlSocket;
        if( proxyname == "none" )
        {// 没有配置代理的情况: none
            if( schema != "http" && 
                schema != "https" )
            {
                printf("fail to parse %s\n", url.c_str());
                return false;
            }

            m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("http"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(schema == "http"? "tcp" : m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: http\n");
                return false;
            }
        }
        else
        {// 已经配置代理的情况: http/socks proxy
            if( proxyname == "http" )
            {// http.proxy
                {
                    std::string ver = m_setsfile.get_string("proxy", "version");
                    if(!ver.empty())
                        ver.insert(0, "/");

                    std::string ssl = m_setsfile.get_string("proxy", "ssl");
                    if(!ssl.empty())
                        ssl.insert(0, ":");

                    CComPtr<IAsynRawSocket> spAsynTmpSocket;
                    m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(proxyname + ver + ssl), &spAsynTmpSocket );
                    if( spAsynTmpSocket == NULL )
                    {
                        printf("can't load plugin: proxy.%s\n", proxyname.c_str());
                        return false;
                    }
                    else
                    {
                        spAsynInnSocket = spAsynTmpSocket;
                    }

                    CComPtr<IAsynProxySocket> spProxy;
                    spAsynInnSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                    asynsdk::CKeyvalSetter    params(1);
                    params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                    HRESULT hr = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", ssl.empty()? 8080 : 8443), STRING_from_string(m_setsfile.get_string("proxy", "method", "")), &params);
                }

                if( schema != "http" &&
                    schema != "https" )
                {
                    m_filepath = url; //use url
                }

                if( schema == "https" )
                {
                    CComPtr<IHttpTxTunnel> spDataTxTunnel; spAsynInnSocket->QueryInterface(IID_IHttpTxTunnel, (void **)&spDataTxTunnel);
                    spDataTxTunnel->SetEnabled(1); //强制直接代理

                    m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("http"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket );
                    if( spAsynPtlSocket == NULL )
                    {
                        printf("can't load plugin: http\n");
                        return false;
                    }
                }
                else
                {
                    spAsynPtlSocket = spAsynInnSocket;
                }
            }
            else
            {// socks.proxy
                if( schema != "http" && 
                    schema != "https" )
                {
                    printf("fail to parse %s\n", url.c_str());
                    return false;
                }

                {
                    std::string ver = m_setsfile.get_string("proxy", "version");
                    if(!ver.empty())
                        ver.insert(0, "/");

                    CComPtr<IAsynRawSocket> spAsynTmpSocket;
                    m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(proxyname + ver), &spAsynTmpSocket );
                    if( spAsynTmpSocket == NULL )
                    {
                        printf("can't load plugin: proxy.%s\n", proxyname.c_str());
                        return false;
                    }
                    else
                    {
                        spAsynInnSocket = spAsynTmpSocket;
                    }

                    CComPtr<IAsynProxySocket> spProxy;
                    spAsynTmpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                    asynsdk::CKeyvalSetter    params(1);
                    params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                    HRESULT hr = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 1080), STRING_from_string(m_setsfile.get_string("proxy", "method", "")), &params);
                }

                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("http"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(schema=="http"? "tcp" : m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket );
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: http\n");
                    return false;
                }
            }
        }

        //设置接收数据速度: B/s
        asynsdk::SetSpeedController(spAsynPtlSocket, Io_recv, -1, m_spSpeedController);

        spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocket, (void **)&m_spAsynTcpSocket);
        m_spAsynTcpSocket->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);

        //开始连接...
        if( proxyname == "none" )
        {
            printf("start to connect %s:%d\n", m_host.c_str(), m_port);
        }
        else
        {
            const PORT port = (PORT)m_setsfile.get_long("proxy", "port", 0);
            if( port )
                printf("start to connect %s:%d via %s-proxyserver[%s:%d]\n", m_host.c_str(), m_port, proxyname.c_str(), m_setsfile.get_string("proxy", "host", "127.0.0.1").c_str(), port);
            else
                printf("start to connect %s:%d via %s-proxyserver[%s]\n", m_host.c_str(), m_port, proxyname.c_str(), m_setsfile.get_string("proxy", "host", "127.0.0.1").c_str());
        }

        CComPtr<IAsynNetIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
        m_spAsynTcpSocket->Connect(STRING_from_string(m_host), m_port, 0, spAsynIoOperation, m_setsfile.get_long("session", "connect_timeout", 2000/*2sec*/));
        return true;
    }

    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;

    CComPtr<ISpeedController> m_spSpeedController;
    uint32_t m_starttime;
    uint32_t m_af;
    bool     m_nochkcert;

    CComPtr<IAsynIoBridge   > m_spAsynIoBridge;
    CComPtr<IAsynTcpSocket  > m_spAsynTcpSocket;

    std::string   m_host;
    PORT          m_port;

    const char   *m_referurl;
    setting       m_setsfile;
    std::string   m_filename;
    std::string   m_filepath;
    std::string   m_savename;
    uint64_t      m_datasize; //尚未接收数据的长度
    uint64_t      m_startpos; //从０开始

public:
    HANDLE m_hNotify;
};

#endif//__HTTPDOWNLOADER_H__
