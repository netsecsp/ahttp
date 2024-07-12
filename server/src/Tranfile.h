#ifndef __TRANFILE_H__
#define __TRANFILE_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 01/15/2024
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
#include <frame/AsynNetwork.h>
using namespace asynsdk;

class CTranfile :
        public asyn_message_events_impl
{
public:
    CTranfile(IAsynIoBridge* lpAsynIoBridge, IAsynIoOperation* lpAsynIoOperation)
      : m_spAsynIoOperation(lpAsynIoOperation), m_spAsynIoBridge(lpAsynIoBridge)
    {
    }
    virtual ~CTranfile()
    {
        asyn_message_events_impl::Stop(0);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CTranfile)
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IUnknown **objects );

public:
    HRESULT Start(uint64_t size)
    {
        return m_spAsynIoBridge->Invoke(size, GetAsynMessageEvents());
    }

protected:
    CComPtr<IAsynIoBridge   > m_spAsynIoBridge;
    CComPtr<IAsynIoOperation> m_spAsynIoOperation;
};

#endif//__TRANFILE_H__
