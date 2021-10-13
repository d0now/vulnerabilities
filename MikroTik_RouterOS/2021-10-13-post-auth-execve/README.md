# RouterOS arbitrary call `execve()` (Post Authentication)
- Affect version : 6.48.3 to 6.48.? (not checked. sorry.)
- Impact : `Low`
- Difficulty : `Low`

## Report (Korean)

본 취약점은...
- MikroTik RouterOS 6.48.3에서 발견되었습니다.
- 디바이스의 설정에 관계 없이 발생합니다.
- `/nova/bin/mepty` 컴포넌트에서 발생합니다.
- `sub_804B2BC()` 함수에서 취약점이 발생합니다.
- 최종적으로, 악의적인 사용자가 임의의 `execve()`를 통해 프로세스를 만들 수 있습니다.

### 코드 분석 (Root cause analysis)
```c++
int sub_804B2BC()
{
    ...

    v52 = nv::message::get<nv::u32_id>(a2, 8);
    v12 = (const string *)nv::message::get<nv::string_id>(a2, 9);
    string::string(&v60, v12); // [1]

    ...

    if ( v59 )
        setenv("TERM", (const char *)(v59 + 4), 1);
    v30 = s // [2]

    ...

    switch (...)
    {
        ...
        case 4:
            snprintf(s, 0x50u, "%s", (const char *)(v60 + 4));
            execl("/nova/bin/telser", "telser", s, 0);
            *(_DWORD *)s = "/nova/bin/telnet";
            argv = "/nova/bin/telnet" + 10;
            v31 = "-4";
            if ( v15 )
                v31 = "-6";
            v71 = v31;
            v30 = (char *)&v72;
            break;
        default:
            break; // [3]
        ...
    }

    ...

    *(_DWORD *)v30 = v60 + 4; // [4]
    *((_DWORD *)v30 + 1) = 0;
    string::string((string *)&v56, *(const char **)s); // [5]
    nv::findFile((nv *)&v55, (const string *)&v56, 0); // [6]
    execv((const char *)(v55 + 4), &argv); // [7]

    ...
}
```
1. `v60`에 9번 인자의 문자열을 할당합니다. (익스플로잇 코드에서 `s9`)
2. `v30`에 `s`를 대입합니다.
3. `default`문에서, **할당 된 변수들을 초기화 하거나, 함수를 끝내는 등 적절한 조치를 취하지 않습니다.**
4. `*v30`에 `v60+4`(문자열의 실제 주소)를 대입합니다.
5. `v56`에 `s`를 할당합니다. 여기서 `s`에는 4번 단계에서 넣은 값(`s9`)이 들어가 있습니다.
6. `execve()`를 통해 원하는 프로세스를 생성할 수 있습니다.

### 악용
- 본 취약점을 활용하여 장비의 관리자 권한을 획득 할 수 있습니다.

### 한계
- 업로드 한 임의의 바이너리에 **실행 권한을 부여하여** 실행해야만 최종적으로 권한을 획득할 수 있습니다.
- 인증(로그인) 후 사용 가능한 취약점입니다.

## Root Cause Analysis (English)
.. ( I'll update english version if someone needs :) ) ..