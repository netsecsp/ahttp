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
#include "stdafx.h"
#include "Service.h"
#include <frame/asm/ISsl.h>

static const std::map<std::string, std::string> s_mapMimes = {
        {".ts"  , "video/MP2T"                   },
        {".flv" , "video/x-flv"                  },
        {".m4v" , "video/x-m4v"                  },
        {".3gpp", "video/3gpp"                   },
        {".3gp" , "video/3gpp"                   },
        {".mp4" , "video/mp4"                    },
        {".aac" , "audio/x-aac"                  },
        {".mp3" , "audio/mpeg"                   },
        {".m4a" , "audio/x-m4a"                  },
        {".ogg" , "audio/ogg"                    },
        {".m3u8", "application/vnd.apple.mpegurl"}, // application/x-mpegURL
        {".rss" , "application/rss+xml"          },
        {".json", "application/json"             },
        {".swf" , "application/x-shockwave-flash"},
        {".doc" , "application/msword"           },
        {".zip" , "application/zip"              },
        {".rar" , "application/x-rar-compressed" },
        {".xml" , "text/xml"                     },
        {".html", "text/html"                    },
        {".js"  , "text/javascript"              },
        {".css" , "text/css"                     },
        {".ico" , "image/x-icon"                 },
        {".png" , "image/png"                    },
        {".jpeg", "image/jpeg"                   },
        {".jpg" , "image/jpeg"                   },
        {".gif" , "image/gif"                    }
};

BEGIN_ASYN_MESSAGE_MAP(CService)
    ON_IOMSG_NOTIFY(OnIomsgNotify)
    ON_QUERY_RESULT(OnQueryResult, IKeyvalSetter)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CService::OnQueryResult( uint64_t lparam1, uint64_t lparam2, IKeyvalSetter **ppKeyval )
{
    if( lparam1 ) return E_NOTIMPL;
 
    asynsdk::CStringSetter d(1);
    ppKeyval[0]->Get(STRING_from_string(";dattype"), 0, 0, &d);

    std::string::size_type ipos;
    if((ipos=d.m_val.rfind("cert.get"   )) != std::string::npos)
    {// cert.get
        if( m_cert_p12.empty()) return S_FALSE;
        ISsl *pSsl = (ISsl *)lparam2;
        STRING certandpasswd[2];
        certandpasswd[0] = STRING_from_string(m_cert_p12);
        certandpasswd[1] = STRING_from_string(m_password);
        pSsl->SetCryptContext(0, 0, certandpasswd);
        ppKeyval[0]->Set(STRING_from_string(";version"), 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")));
        return S_OK;
    }

    if((ipos=d.m_val.rfind("cert.verify")) != std::string::npos)
    {// cert.verify
        return S_OK;
    }

    return E_NOTIMPL;
}

HRESULT CService::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR, lTransferedBytes;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, &lTransferedBytes, 0);

    switch(lAction)
    {
        case Io_acceptd:
        {
            if( lErrorCode != NO_ERROR )
            {
                printf("accept, error: %d\n", lErrorCode);
                m_spAsynTcpSocketListener[lParam1? 1 : 0]->Accept(lpAsynIoOperation);
                return S_OK;
            }
            else
            {// 新客户端
                std::string host; asynsdk::CStringSetterRef temp(1, &host);
                PORT        port;

                CComPtr<IAsynNetIoOperation> spAsynIoOperation;
                lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->GetPeerAddress(&temp, 0, &port, 0);
                printf("accepted new client from %s:%d\n", host.c_str(), port);

                char skey[64]; sprintf_s(skey, 64, "%s:%d", host.c_str(), port);
                userinfo &info = m_arId2Userinfos[skey];
                info.skey = skey;

                //提取连接IAsynTcpSocket
                lpAsynIoOperation->GetCompletedObject(TRUE, IID_INet, (void **)&info.spDataTcpSocket);
                m_spAsynTcpSocketListener[lParam1? 1 : 0]->Accept(lpAsynIoOperation);

                //控制连接发送速度: B/s
                m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (void **)&info.spSpeedController);
                info.spSpeedController->SetMaxSpeed(m_setsfile.get_long("session", "max_sendspeed", -1));
                bool ret = asynsdk::SetSpeedController(info.spDataTcpSocket, Io_send, -1, info.spSpeedController);

                CComPtr<IAsynIoOperation> spRecvIoOperation;
                m_spAsynFrame->CreateAsynIoOperation(0, 0, &spRecvIoOperation);
                m_arOp2Userinfos[spRecvIoOperation] = &info;

                spRecvIoOperation->SetIoParam1(0); //准备接收http报文头部
                return info.spDataTcpSocket->Read(spRecvIoOperation);
            }
        }

        case Io_send:
        {
            userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];

            if( lErrorCode != NO_ERROR )
            {
                printf("send, error: %d\n", lErrorCode);
            }
            else
            {
                uint32_t speed;
                info->spSpeedController->GetPostIoBytes(0, &speed);
                printf("send complete, speed: %.2fKB/s, cost: %dms\n", speed / 1024.0, ::GetTickCount() - info->starttime);
                if( lParam1 != 0/*Keep-Alive*/ )   //长连接的处理
                {
                    info->tranfile = NULL;
                    lpAsynIoOperation->SetIoParam1(0); //准备接收http报文头部
                    return info->spDataTcpSocket->Read(lpAsynIoOperation);
                }
            }

            printf("remove client: %s\n", info->skey.c_str());
            m_arOp2Userinfos.erase(lpAsynIoOperation);
            m_arId2Userinfos.erase(info->skey);
            break;
        }

        case Io_recv:
        {
            userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];
            if( lErrorCode != NO_ERROR )
            {
                if( lErrorCode != AE_RESET ) printf("recv, error: %d\n", lErrorCode);
                printf("remove client: %s\n", info->skey.c_str());
                m_arOp2Userinfos.erase(lpAsynIoOperation);
                m_arId2Userinfos.erase(info->skey);
                break;
            }
            else
            {
                //接收来自客户端的HTTP请求
                CComPtr<INetmsg> spReqmsg;
                lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (void **)&spReqmsg);

                STRING Method;
                STRING Params;
                STRING V;
                spReqmsg->Getline(&Method, &Params, &V, 0 );
                std::string method = string_from_STRING(Method);
                std::string params = string_from_STRING(Params);
                std::string v = string_from_STRING(V);

    #ifdef _DEBUG
                printf("rcv http req packet from %s\n", info->skey.c_str());
                printf("%s %s %s\n", method.c_str(), params.c_str(), v.c_str());
    #endif

                asynsdk::CStringSetterRef s(1, &params);
                spReqmsg->Get(STRING_from_string(";value_ansi"), 0, 0, &s); //获取params的CP_ACP编码格式

                if( params == "/" ||
                    params.empty() ) params = "/index.html";

                const std::string &filename = m_setsfile.get_string("website", "home") + params;
                asynsdk::CStringSetter    c(1);
                spReqmsg->Get(STRING_from_string("Connection"), 0, 0, c.Clear());
                lpAsynIoOperation->SetOpParams(AF_IOMSG_NOTIFY, 0, Io_send); //设置传输完成通知事件
                lpAsynIoOperation->SetOpParam1(c.m_val != "Keep-Alive" ? 0 : 1);

                CComPtr<IAsynFile> spAsynFile;
                m_spAsynFileSystem->CreateAsynFile(&spAsynFile );
                HRESULT r1 = spAsynFile->Open( m_spAsynFrameThread,
                                       STRING_from_string(filename),
                                       GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
                if( r1 != S_OK )
                {
                    printf("open %s, error: %d\n", filename.c_str(), ::GetLastError());
                    info->spDataTcpSocket->SendPacket(STRING_from_string("404"), STRING_from_string("Not Found"), 0, 0);
                    return asynsdk::PostAsynIoOperation(lpAsynIoOperation,404);
                }
                else
                {
                    asynsdk::CKeyvalSetter params(1);

                    std::string::size_type ipos = filename.rfind('.');
                    if( std::string::npos != ipos )
                    {
                        std::map<std::string, std::string>::const_iterator it = s_mapMimes.find(filename.substr(ipos));
                        if( it != s_mapMimes.end()) params.Set(STRING_from_string("Content-type"), 1, STRING_from_string(it->second));
                    }

                    uint64_t filesize; spAsynFile->GetFileSize(&filesize );

                    char out[128];
                    uint64_t sendpos = 0;
                    uint64_t sendend = filesize - 1;

                    if( spReqmsg->Get(STRING_from_string("Range"), 0, 0, c.Clear()) != S_OK )
                    {
                        _i64toa_s(filesize, out, sizeof(out), 10);
                        params.Set(STRING_from_string("Content-Length"), 1, STRING_from_string(out));

                        info->spDataTcpSocket->SendPacket(STRING_from_string("200"), STRING_from_string("OK"), &params, 0);
                        if( filesize == 0 )   //文件大小等于0的情况: 模拟发送完成
                        {
                            info->starttime = ::GetTickCount();
                            return asynsdk::PostAsynIoOperation(lpAsynIoOperation, NO_ERROR);
                        }
                    }
                    else
                    {// Range: bytes=5275648-
                        std::string::size_type ipos = c.m_val.find('=');
                        if( std::string::npos != ipos )
                        {
                            sendpos = _atoi64(c.m_val.c_str() + ipos + 1);
                            ipos = c.m_val.find('-', ipos);
                            if( std::string::npos != ipos )
                            {
                                ipos = c.m_val.find_first_of("0123456789", ipos);
                                if( std::string::npos != ipos )
                                {
                                    sendend = _atoi64(c.m_val.c_str() + ipos);
                                }
                            }
                        }

                        if( sendpos >  sendend ||
                            sendpos >= filesize || sendend >= filesize )   //字段非法
                        {
                            info->spDataTcpSocket->SendPacket(STRING_from_string("403"), STRING_from_string("Forbidden"), &params, 0);
                            return asynsdk::PostAsynIoOperation(lpAsynIoOperation, 403);
                        }

                        //Content-Range: bytes 5275648-15143085/15143086
                        sprintf_s(out, 128, "bytes %I64d-%I64d/%I64d", sendpos, sendend, filesize);
                        params.Set(STRING_from_string("Content-Range" ), 1, STRING_from_string(out));

                        _i64toa_s(sendend + 1 - sendpos, out, sizeof(out), 10);
                        params.Set(STRING_from_string("Content-Length"), 1, STRING_from_string(out));

                        info->spDataTcpSocket->SendPacket(STRING_from_string("206"), STRING_from_string("Partial Content"), &params, 0);
                    }

                    CComPtr<IAsynIoBridge> spAsynIoBridge;
                    m_spAsynFrameThread->CreateAsynIoBridge(spAsynFile, info->spDataTcpSocket, 0, &spAsynIoBridge);
                    if( sendpos )
                    {
                        CComPtr<IAsynFileIoOperation> spAsynIoOperation; spAsynIoBridge->Get(BT_GetSourceIoOperation, 0, IID_IAsynFileIoOperation, (void**)&spAsynIoOperation);
                        spAsynIoOperation->SetPosition(sendpos); //设置开始读取数据时文件的偏移
                    }
                    
                    info->tranfile.reset(new CTranfile(spAsynIoBridge, lpAsynIoOperation));
                    printf("start to send %s from %I64d-%I64d/%I64d\n", filename.c_str(), sendpos, sendend, filesize);
                    info->starttime = ::GetTickCount();
                    return info->tranfile->Start(sendend - sendpos + 1);
                }
            }
        }
    }
    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}


