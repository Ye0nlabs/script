#!/bin/bash

OS=$(sudo cat /etc/os-release | grep -Po '^ID=("?\K[^"]*)')
OS_VERSION=$(sudo cat /etc/os-release | grep -Po '^VERSION_ID=("?\K[^"]*)')
OS_TYPE=$(sudo cat /etc/os-release | grep -Po '^ID_LIKE=("?\K[^"]*)' | tr '[:upper:]' '[:lower:]')
HOST=`hostname`
IP_ADDR=`hostname -I`
date=$(date)
CHECK_TIME=$(date +%Y%m%d_%H%M%S)
CHECK_PATH=`pwd`
RESULT_DIR=${CHECK_PATH}/vuln_report
RESULT=${RESULT_DIR}/${HOST}__LINUX__RESULT_${CHECK_TIME}.txt

if [ ! -d ${RESULT_DIR} ]; then
  mkdir -p ${RESULT_DIR}
fi

declare -A COUNT
COUNT=(
    ["VULN"]=0
    ["SECURE"]=0
    ["SELF"]=0
)
banner(){
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
    echo "                     LINUX VULNERABILITY CHECK REPORT" >> $RESULT
    echo "" >> $RESULT
    echo "                  © Copyright ye0n. All rights reserved." >> $RESULT
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
    echo " Date: ${date}" >> $RESULT
    echo " Host: ${HOST}" >> $RESULT
    echo " OS: $OS $OS_VERSION" >> $RESULT
    echo " IP Address: ${IP_ADDR}" >> $RESULT
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_1(){
    echo "■ U-01. root 계정 원격 접속 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우" >> $RESULT
    echo "[취약] : 원격터미널 서비스 사용 시 root 직접 접속을 허용한 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    telnet_check1(){
        echo "★ Telnet" >> $RESULT
        echo "" >> $RESULT
        echo "1) /etc/pam.d/login 파일 점검" >> $RESULT
        CONFIG_FILE=$(ls /etc/pam.d/login 2>/dev/null | wc -l)
        if [ $CONFIG_FILE -gt 0 ]; then
            VALUE=$(sudo cat /etc/pam.d/login 2>/dev/null | grep -i "/lib/security/pam_securetty.so" | grep -v "#" | wc -l)
            if [ $VALUE -lt 1 ]; then
                VULN=1
                echo -e "/etc/pam.d/login 파일 내 root 계정 원격 터미널 로그인 제한 설정이\n존재하지 않습니다." >> $RESULT
            else
                sudo cat /etc/pam.d/login 2>/dev/null | grep -i "/lib/security/pam_securetty.so" | grep -v "#" >> $RESULT
            fi
        else
            echo "/etc/pam.d/login 파일이 존재하지 않습니다." >> $RESULT
        fi
        echo "" >> $RESULT
    }
    telnet_check2(){
        echo "2) /etc/securetty 파일 점검" >> $RESULT
        CONFIG_FILE=$(ls /etc/securetty 2>/dev/null | wc -l)
        if [ $CONFIG_FILE -gt 0 ]; then
            VALUE=$(sudo cat /etc/securetty 2>/dev/null | grep -i "pts" | grep -v "#" | wc -l)
            if [ $VALUE -gt 0 ]; then
                VULN=1
                sudo cat /etc/securetty 2>/dev/null | grep -i "pts" | grep -v "#" >> $RESULT
            else
                echo "/etc/securetty 파일 내 pts/x 설정이 존재하지 않습니다." >> $RESULT
            fi
        else
            echo "/etc/securetty 파일이 존재하지 않습니다." >> $RESULT
        fi
        echo "" >> $RESULT
    }
    ssh_check(){
        echo "★ SSH" >> $RESULT
        CONFIG_FILE=$(ls /etc/ssh/sshd_config 2>/dev/null | wc -l)
        if [ $CONFIG_FILE -gt 0 ]; then
            VALUE=$(sudo cat /etc/ssh/sshd_config 2>/dev/null | grep -i "PermitRootLogin" | grep -v "#")
            if [ -n "$VALUE" ] && [ `echo $VALUE | grep -i "no" | wc -l` -lt 1 ]; then
                VULN=1
                echo "$VALUE" >> $RESULT
            else
                if [ -z "$VALUE" ]; then
                    VULN=1
                    echo -e "/etc/ssh/sshd_config 파일 내 root 계정 원격 접속 제한 설정이\n존재하지 않습니다." >> $RESULT
                else
                    echo "$VALUE" >> $RESULT
                fi
            fi
        else
            echo "/etc/ssh/sshd_config 파일이 존재하지 않습니다." >> $RESULT
        fi
    }
    telnet_status(){
        if systemctl is-active --quiet telnet.socket; then
            VALUE=0
        else
            VALUE=1
        fi
        return $VALUE
    }
    if [ `echo $OS | grep -i "centos" | wc -l` -gt 0 ] && [ $OS_VERSION -ge 8 ]
    then
        telnet_status
        if [ $? -eq 1 ]; then
            telnet_check1
            ssh_check
        else
            ssh_check
        fi
    elif [ `echo $OS | grep -i "ubuntu" | wc -l` -gt 0 ] && [ `echo $OS_VERSION | awk -F "." '{print $1}'` -ge 20 ]; then
        telnet_status
        if [ $? -eq 1 ]; then
            telnet_check1
            ssh_check
        else
            ssh_check
        fi
    else
        telnet_status
        if [ $? -eq 1 ]; then
            telnet_check1
            telnet_check2
            ssh_check
        else
            ssh_check
        fi
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_2(){
	echo "■ U-02. 비밀번호 관리정책 설정" >> $RESULT
	echo "" >> $RESULT
    echo "[양호] : 비밀번호 관리 정책이 설정된 경우" >> $RESULT
    echo "[취약] : 비밀번호 관리 정책이 설정되지 않은 경우" >> $RESULT
    echo "" >> $RESULT
	
	VULN=0

	echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
	
	#1. PASS_MAX_DAYS / PASS_MIN_DAYS
	pass_period_check(){
		sudo cat /etc/login.defs 2>/dev/null | grep -i "PASS_MAX_DAYS" | grep -v "#" >> $RESULT
        sudo cat /etc/login.defs 2>/dev/null | grep -i "PASS_MIN_DAYS" | grep -v "#" >> $RESULT
		
		PASS_MAX_DAYS=$(sudo cat /etc/login.defs 2>/dev/null | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk -F " " '{print $2}')
		PASS_MIN_DAYS=$(sudo cat /etc/login.defs 2>/dev/null | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk -F " " '{print $2}')
		
		if [[ $PASS_MAX_DAYS -gt 90 ]] || [[ $PASS_MIN_DAYS -lt 1 ]]; then
            VULN=1
        fi
	}
	
	#2. /etc/security/pwquality.conf 파일 점검
    pass_conf_check(){
        declare -A VALUES
        VALUES=(
            ["minlen"]=8
            ["dcredit"]=-1
            ["ucredit"]=-1
            ["lcredit"]=-1
            ["ocredit"]=-1
            ["enforce_for_root"]="enforce_for_root"
        )

        for val in ${!VALUES[@]}; do
            VAR=$(sudo cat /etc/security/pwquality.conf | grep -i $val | awk -F " " '{print $4}')
            sudo cat /etc/security/pwquality.conf | grep -i $val >> $RESULT
            if [[ $VAR != ${VALUES[$val]} ]]; then
                VULN=1
            fi
        done
    }
	pass_conf_check
	pass_period_check

	echo "" >> $RESULT
    echo "" >> $RESULT

	if [ $VULN -eq 1 ]; then
		echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
	else
		echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
	fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_3(){
    echo "■ U-03. 계정 잠금 임계값 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 계정 잠금 임계값이 10회 이하의 값으로 설정된 경우" >> $RESULT
    echo -e "[취약] : 계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    if [ `ls /etc/pam.d/system-auth 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/pam.d/system-auth 2>/dev/null | grep -v "#" | grep -i "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/')
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "계정 잠금 임계값이 설정되어 있지 않습니다." >> $RESULT
        else
            sudo cat /etc/pam.d/system-auth 2>/dev/null | grep -v "#" | grep -i "deny=" >> $RESULT
        fi
    elif [ `ls /etc/securiy/faillock.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/securiy/faillock.conf 2>/dev/null | grep -v "#" | grep -i "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/')
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "계정 잠금 임계값이 설정되어 있지 않습니다." >> $RESULT
        else
            sudo cat /etc/securiy/faillock.conf | grep -v "#" | grep -i "deny=" >> $RESULT
        fi
    elif [ `ls /etc/pam.d/password-auth 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/pam.d/password-auth 2>/dev/null | grep -v "#" | grep -i "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/')
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "계정 잠금 임계값이 설정되어 있지 않습니다." >> $RESULT
        else
            sudo cat /etc/pam.d/password-auth | grep -v "#" | grep -i "deny=" >> $RESULT
        fi
    elif [ `ls /etc/pam.d/common-auth 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/pam.d/common-auth | grep -v "#" | grep -i "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/')
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "계정 잠금 임계값이 설정되어 있지 않습니다." >> $RESULT
        else
            sudo cat /etc/pam.d/common-auth | grep -v "#" | grep -i "deny=" >> $RESULT
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ -z "$VALUE" ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    elif [ "$VALUE" -le 10 ] && [ "$VALUE" -gt 0 ]; then
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    else
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_4(){
    echo "■ U-04. 비밀번호 파일 보호" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우" >> $RESULT
    echo -e "[취약] : 쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    not_shadow=$(sudo cat /etc/passwd | awk -F ":" '{print $2}' | grep -v "x" | wc -l)
    not_encrypt=$(sudo cat /etc/shadow | awk -F: '$2 !~ /^(\$|\*|!)/' | wc -l)

    sudo tail -1 /etc/passwd >> $RESULT
    sudo cat /etc/shadow | awk -F: '$2 !~ /^(\$|\*|!)/' >> $RESULT
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    if [ $not_shadow -gt 0 ]; then
        if [ $not_encrypt -gt 0 ]; then
            echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
            ((COUNT["VULN"]++))
        else
            echo "※ 점검 결과: 양호(Secure)" >> $RESULT
            ((COUNT["SECURE"]++))
        fi
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_5(){
    echo "■ U-05. root 이외의 UID가 '0' 금지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $RESULT
    echo -e "[취약] : root 계정과 동일한 UID를 갖는 계정이 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    
    VALUE=$(sudo cat /etc/passwd | grep -v "root" | awk -F: '$3 == 0' | wc -l)
    sudo cat /etc/passwd | awk -F: '$3 == 0' >> $RESULT
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    if [ $VALUE -gt 0 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_6(){
    echo "■ U-06. 사용자 계정 su 기능 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우" >> $RESULT
    echo -e "[취약] : su 명령어를 모든 사용자가 사용하도록 설정된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    USE_PAM=$(ls -d /etc/pam.d | wc -l)
    
    if [ $USE_PAM -gt 0 ]; then
        if [ `sudo cat /etc/group | grep -i "wheel" | wc -l` -gt 0 ]; then
            sudo cat /etc/group | grep -i "wheel" >> $RESULT
        else
            echo "wheel 그룹이 존재하지 않습니다." >> $RESULT
        fi
    else
        sudo cat ls -l /usr/bin/su >> $RESULT
        if [ `sudo cat /etc/group | grep -i "wheel" | wc -l` -gt 0 ]; then
            sudo cat /etc/group | grep -i "wheel" >> $RESULT
        else
            echo "wheel 그룹이 존재하지 않습니다." >> $RESULT
        fi
    fi
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_7(){
    echo "■ U-07. 불필요한 계정 제거" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 불필요한 계정이 존재하지 않는 경우" >> $RESULT
    echo -e "[취약] : 불필요한 계정이 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    sudo cat /etc/passwd | awk -F ":" '{print $1}' >> $RESULT
    echo "" >> $RESULT
    last >> $RESULT
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}

U_8(){
    echo "■ U-08. 관리자 그룹에 최소한의 계정 포함" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> $RESULT
    echo -e "[취약] : 관리자 그룹에 불필요한 계정이 등록된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    sudo cat /etc/group | grep -i "root" >> $RESULT
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
} 
U_9(){
    echo "■ U-09. 계정이 존재하지 않는 GID 금지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 시스템 관리나 운용에 불필요한 그룹이 제거된 경우" >> $RESULT
    echo -e "[취약] : 시스템 관리나 운용에 불필요한 그룹이 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    sudo cat /etc/group >> $RESULT
    echo "" >> $RESULT
    sudo cat /etc/gshadow >> $RESULT
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_10(){
    echo "■ U-10. 동일한 UID 금지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $RESULT
    echo -e "[취약] : 동일한 UID로 설정된 사용자 계정이 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    DUPL_UID=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [ -n "$DUPL_UID" ]; then
        sudo cat /etc/passwd | grep $DUPL_UID >> $RESULT
        VULN=1
    else
        echo "동일한 UID로 설정된 사용자 계정이 존재하지 않습니다." >> $RESULT
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_11(){
    echo "■ U-11. 사용자 shell 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우" >> $RESULT
    echo -e "[취약] : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    
    VALUE=$(sudo cat /etc/passwd | grep -E "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v admin)
    echo "$VALUE" >> $RESULT
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    if [ `echo $VALUE | grep -Ev "/bin/false|/sbin/nologin" | wc -l` -gt 0 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_12(){
    echo "■ U-12. 세션 종료 시간 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : Session Timeout이 600초(10분) 이하로 설정된 경우" >> $RESULT
    echo -e "[취약] : Session Timeout이 600초(10분) 이하로 설정되지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    SHELL_NAME=$(basename "$SHELL")

    if [ "$SHELL_NAME" == "sh" ] || [ "$SHELL_NAME" == "ksh" ] || [ "$SHELL_NAME" == "bash" ]; then
        VALUE=$(sudo cat /etc/profile | grep "TMOUT" | grep  -v "#" | awk -F "=" '{print $2}')
        if [ -z "$VALUE" ]; then
            echo "Session Timeout이 설정되어 있지 않습니다." >> $RESULT
            VULN=1
        else
            sudo cat /etc/profile | grep "TMOUT=" | grep  -v "#" >> $RESULT
            if [ "$VALUE" -gt 600 ]; then
                VULN=1
            fi
        fi
    else
        VALUE=$(sudo cat /etc/csh.cshrc /etc/csh.login 2>/dev/null | grep -E "^\s*set\s+autologout\s*=" | head -n1 | awk '{print $4}')
        if [ -z "$VALUE" ]; then
            echo "Session Timeout이 설정되어 있지 않습니다." >> $RESULT
            VULN=1
        else
            sudo cat /etc/csh.cshrc /etc/csh.login 2>/dev/null | grep -E "^\s*set\s+autologout\s*=" | grep  -v "#" >> $RESULT
            if [ "$VALUE" -gt 10 ]; then
                VULN=1
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_13(){
    echo "■ U-13. 안전한 비밀번호 암호화 알고리즘 사용" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우" >> $RESULT
    echo -e "[취약] : 취약한 비밀번호 암호화 알고리즘을 사용하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `sudo cat /etc/login.defs | grep -i "ENCRYPT_METHOD" | grep -v "#" | awk -F " " '{print $2}' | wc -l` -gt 0 ]; then
        ENCRYPT_ALG=$(sudo cat /etc/login.defs | grep -i "ENCRYPT_METHOD" | grep -v "#" | awk -F " " '{print $2}' | tr '[:lower:]' '[:upper:]')
        echo $ENCRYPT_ALG >> $RESULT
        if [ "$ENCRYPT_ALG" != "SHA256" ] && [ "$ENCRYPT_ALG" != "SHA512" ]; then
            VULN=1
        fi
    else
        ENCRYPT_ALG=$(sudo cat /etc/shadow | awk -F: '$2 ~ /^\$/ {split($2, a, "$"); print a[2]}' | uniq)
        SECURE_ALG=("SHA-256" "SHA-512" "yescrypt")
        if [ "$ENCRYPT_ALG" != "5" ] && [ "$ENCRYPT_ALG" != "6" ] && [ "$ENCRYPT_ALG" != "y" ]; then
            VULN=1
        fi

        if [ "$ENCRYPT_ALG" == "5" ]; then
            echo "SHA-256 암호화 알고리즘을 사용하고 있습니다." >> $RESULT
        elif [ "$ENCRYPT_ALG" == "6" ]; then
            echo "SHA-512 암호화 알고리즘을 사용하고 있습니다." >> $RESULT
        elif [ "$ENCRYPT_ALG" == "y" ]; then
            echo "yescrypt 해싱 알고리즘을 사용하고 있습니다." >> $RESULT
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_14(){
    echo "■ U-14. root 홈, 패스 디렉터리 권한 및 패스 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되지 않은 경우" >> $RESULT
    echo -e "[취약] : PATH 환경변수에 "." 이 맨 앞이나 중간에 포함된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    CURRENT_PATH=$(echo $PATH)
    VULN=0
    echo $CURRENT_PATH >> $RESULT
    
    if [[ $CURRENT_PATH =~ ^\.: ]] || [[ $CURRENT_PATH == "." ]]; then
        VULN=1
    elif [[ $CURRENT_PATH =~ :.: ]] || [[ $CURRENT_PATH =~ :\.: ]]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_15(){
    echo "■ U-15. 파일 및 디렉터리 소유자 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우" >> $RESULT
    echo -e "[취약] : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(sudo find / \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null)
    
    if [ -z "$VALUE" ]; then
        echo "소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        VULN=1
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_16(){
    echo "■ U-16. /etc/passwd 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    ls -l /etc/passwd >> $RESULT
    
    FILE_OWNER=$(ls -l /etc/passwd | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/passwd)
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ "$FILE_OWNER" != "root" ]; then
        VULN=1
    else
        if [ "$FILE_PERM" -gt 644 ]; then
            VULN=1
        fi
    fi
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_17(){
    echo "■ U-17. 시스템 시작 스크립트 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우" >> $RESULT
    echo -e "[취약] : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    PROC=$(ps -p 1 -o comm=)

    if [ "$PROC" == "init" ]; then
        ls -al 2>/dev/null `readlink -f /etc/rc.d/*/* | sed 's/$/*/'` >> $RESULT
        FILE_OWNER=$(ls -al 2>/dev/null `readlink -f /etc/rc.d/*/* | sed 's/$/*/'` | awk -F " " '{print $3!="root"}')
        FILE_PERM=$(stat -c "%a %n" 2>/dev/null `readlink -f /etc/rc.d/*/*` | awk '$1 > 644 {print $1}')
    elif [ "$PROC" == "systemd" ]; then
        ls -al 2>/dev/null `readlink -f /etc/systemd/system/* | sed 's/$/*/'` >> $RESULT
        FILE_OWNER=$(ls -al 2>/dev/null `readlink -f /etc/systemd/system/* | sed 's/$/*/'` | awk -F " " '{print $3!="root"}')
        FILE_PERM=$(stat -c "%a %n" 2>/dev/null `readlink -f /etc/systemd/system/*` | awk '$1 > 644 {print $1}')
    fi

    if [ -n "$FILE_OWNER" ]; then
        VULN=1
    else
        if [ -n "$FILE_PERM" ]; then
            VULN=1
        fi
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_18(){
    echo "■ U-18. /etc/shadow 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    ls -l /etc/shadow >> $RESULT
    
    FILE_OWNER=$(ls -l /etc/shadow | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/shadow)

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 400 ]; then
        VULN=1
    fi
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_19(){
    echo "■ U-19. /etc/hosts 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    ls -l /etc/hosts >> $RESULT
    
    FILE_OWNER=$(ls -l /etc/hosts | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/hosts)

    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 644 ]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_20(){
    echo "■ U-20. /etc/(x)inetd.conf 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/(x)inetd.conf 파일의 소유자가 root가 아니거나,\n권한이 600 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    FILE_OWNER=$(ls -l /etc/inetd.conf /etc/xinetd.conf 2>/dev/null | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/inetd.conf /etc/xinetd.conf 2>/dev/null)
    
    if [ -z "$FILE_OWNER" ]; then
        echo "/etc/(x)inetd.conf 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /etc/inetd.conf /etc/xinetd.conf 2>/dev/null >> $RESULT
        if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 600 ]; then
            VULN=1
        fi
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_21(){
    echo "■ U-21. /etc/(r)syslog.conf 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고,\n권한이 640 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나,\n권한이 640 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    FILE_OWNER=$(ls -l /etc/syslog.conf /etc/rsyslog.conf 2>/dev/null | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/syslog.conf /etc/rsyslog.conf 2>/dev/null)
    
    if [ -z "$FILE_OWNER" ]; then
        echo "/etc/(r)syslog.conf 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /etc/syslog.conf /etc/rsyslog.conf 2>/dev/null >> $RESULT
        if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "bin" ] && [ "$FILE_OWNER" != "sys" ]; then
            VULN=1
        fi
        if [ "$FILE_PERM" -gt 640 ]; then
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_22(){
    echo "■ U-22. /etc/services 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/services 파일의 소유자가 root(또는 bin, sys)이고,\n권한이 644 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나,\n권한이 644 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    ls -l /etc/services >> $RESULT
    FILE_OWNER=$(ls -l /etc/services | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/services)

    if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "bin" ] && [ "$FILE_OWNER" != "sys" ]; then
            VULN=1
        if [ "$FILE_PERM" -gt 644 ]; then
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_23(){
    echo "■ U-23. SUID, SGID, Sticky bit 설정 파일 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우" >> $RESULT
    echo -e "[취약] : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    sudo find / -user root -type f \( -perm -04000 -o -perm -02000 \) -ls 2>/dev/null | head -20 >> $RESULT
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_24(){
    echo "■ U-24. 사용자, 시스템 환경변수 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로\n지정되어 있고,홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우" >> $RESULT
    echo -e "[취약] : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로\n지정되지 않거나, 홈 디렉터리 환경변수 파일에 root 계정과 소유자 외에 쓰기 권한이 부여된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    ls -l $HOME/.profile $HOME/.kshrc $HOME/.cshrc $HOME/.bashrc $HOME/.bash_profile $HOME/.login $HOME/.exrc $HOME/.netrc 2>/dev/null >> $RESULT
    FILE_OWNER=$(ls -l $HOME/.profile $HOME/.kshrc $HOME/.cshrc $HOME/.bashrc $HOME/.bash_profile $HOME/.login $HOME/.exrc $HOME/.netrc 2>/dev/null | awk -F " " '{print $3}')
    OTHERS_PERM=$(ls -l $HOME/.profile $HOME/.kshrc $HOME/.cshrc $HOME/.bashrc $HOME/.bash_profile $HOME/.login $HOME/.exrc $HOME/.netrc 2>/dev/null | awk -F " " '{print $1}' | awk -F "" '{print $9}')
    CURRENT_USER=$(whoami)
    if [ `echo $FILE_OWNER | grep $CURRENT_USER | wc -l` -lt 1 ] && [ `echo $FILE_OWNER | grep "root" | wc -l` -lt 1 ]; then
        VULN=1
    fi
    if [ `echo $OTHERS_PERM | grep -v "-" | wc -l` -gt 0 ]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_25(){
    echo "■ U-25. world writable 파일 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우" >> $RESULT
    echo -e "[취약] : world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    sudo find / -type f -perm -2 -ls 2>/dev/null | head -20 >> $RESULT
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_26(){
    echo "■ U-26. /dev에 존재하지 않는 device 파일 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우" >> $RESULT
    echo -e "[취약] : /dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    VALUE=$(sudo find /dev -type f -exec ls -l {} \; 2>/dev/null)

    if [ -z "$VALUE" ]; then
        echo "/dev 디렉터리 내 파일이 존재하지 않습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        VULN=1
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_27(){
    echo "■ U-27. $HOME/.rhosts, hosts.equiv 사용 금지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우" >> $RESULT
    echo -e "1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우" >> $RESULT
    echo -e "2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600 이하인 경우" >> $RESULT
    echo -e "3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에 "+" 설정이 없는 경우" >> $RESULT
    echo "" >> $RESULT
    echo -e "[취약] : rlogin, rsh, rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우" >> $RESULT
    echo -e "1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우" >> $RESULT
    echo -e "2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600을 초과한 경우" >> $RESULT
    echo -e "3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에 "+" 설정이 존재하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    CURRENT_USER=$(whoami)
    FILE_OWNER=$(ls -l /etc/hosts.equiv $HOME/.rhosts 2>/dev/null | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/hosts.equiv $HOME/.rhosts 2>/dev/null)
    FILE_CONF=$(sudo cat /etc/hosts.equiv $HOME/.rhosts 2>/dev/null | grep "+" | grep -v "#")
    
    if [ `ls -l /etc/hosts.equiv $HOME/.rhosts 2>/dev/null | wc -l` -gt 0 ]; then
        if [ `ls -l /etc/xinetd.d/ 2>/dev/null | wc -l` -gt 0 ]; then
            EXIST_R=$(ls -l /etc/xinetd.d/ | grep -E 'rsh|rlogin|rexec' | awk -F " " '{print $9}')
            ACTIVE_R=$(sudo cat $EXIST_R | grep -i 'disable' | grep -v "#")
            if [ `echo $ACTIVE_R | wc -l` -lt 1 ]; then
                if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "${CURRENT_USER}" ]; then
                    VULN=1
                elif [ "$FILE_PERM" -gt 600 ]; then
                    VULN=1
                elif [ `echo $FILE_CONF | wc -l` -gt 0 ]; then
                    VULN=1
                fi
            fi
        elif [ `ls -l /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
            ACTIVE_R=$(ls -l /etc/inetd.conf | grep -E 'shell|login|exec' | grep -v "#")
            if [ `echo $ACTIVE_R | wc -l` -gt 0 ]; then
                if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "${CURRENT_USER}" ]; then
                    VULN=1
                elif [ "$FILE_PERM" -gt 600 ]; then
                    VULN=1
                elif [ `echo $FILE_CONF | wc -l` -gt 0 ]; then
                    VULN=1
                fi
            fi
        fi
        echo "★ /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자" >> $RESULT
        echo $FILE_OWNER >> $RESULT
        echo "" >> $RESULT
        echo "★ /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한" >> $RESULT
        echo $FILE_PERM >> $RESULT
        echo "" >> $RESULT
        echo "★ /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에 "+" 설정" >> $RESULT
        if [ -z "$FILE_CONF" ]; then
            echo "'+' 설정이 존재하지 않습니다." >> $RESULT
        else
            echo $FILE_CONF >> $RESULT
        fi
    else
        echo "/etc/hosts.equiv, \$HOME/.rhosts 파일이 존재하지 않습니다." >> $RESULT
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_28(){
    echo "■ U-28. 접속 IP 및 포트 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우" >> $RESULT
    echo -e "[취약] : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정하지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    if [ `ls /etc/hosts.deny 2>/dev/null | wc -l` -gt 0 ]; then
        sudo cat /etc/hosts.deny >> $RESULT
    elif [ `sudo iptables -L -n -v 2>/dev/null | wc -l` -gt 0 ]; then
        sudo iptables -L >> $RESULT
    elif [ `sudo ufw status | grep -i "inactive" | wc -l` -lt 0 ]; then
        sudo ufw status numbered >> $RESULT
    else
        sudo firewall-cmd --list-all >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_29(){
    echo "■ U-29. hosts.lpd 파일 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시\n/etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우" >> $RESULT
    echo -e "[취약] : /etc/hosts.lpd 파일이 존재하며, 파일의 소유자가\nroot가 아니거나, 권한이 600 이하가 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    FILE_OWNER=$(ls -l /etc/hosts.lpd 2>/dev/null | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/hosts.lpd 2>/dev/null)
    
    if [ -z "$FILE_OWNER" ]; then
        echo "/etc/hosts.lpd 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /etc/hosts.lpd >> $RESULT
        if [ "$FILE_OWNER" != "root" ]; then
            VULN=1 
        elif [ "$FILE_PERM" -gt 600 ]; then
            VULN=1
        fi
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_30(){
    echo "■ U-30. UMASK 설정 관리" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : UMASK 값이 022 이상으로 설정된 경우" >> $RESULT
    echo -e "[취약] : UMASK 값이 022 미만으로 설정된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    CURRENT_UMASK=$(umask)
    echo "UMASK $CURRENT_UMASK" >> $RESULT

    if [ "$CURRENT_UMASK" != "0022" ]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_31(){
    echo "■ U-31. 홈디렉토리 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우" >> $RESULT
    echo -e "[취약] : 홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    
    mapfile -t HOME_DIR < <(sudo awk -F ":" '{print $6}' /etc/passwd)
    mapfile -t USERS < <(sudo awk -F ":" '{print $1}' /etc/passwd)
    for ((i=0; i<${#HOME_DIR[@]}; i++)) do
        ls -ld ${HOME_DIR[$i]} 2>/dev/null >> $RESULT
        if [ `ls -ld ${HOME_DIR[$i]} 2>/dev/null | awk '$3 != "${USERS[$i]}" {print $3}' | wc -l` -gt 0 ]; then
            VULN=1
        elif [ `ls -ld ${HOME_DIR[$i]} 2>/dev/null | awk -F " " '{print $1}' | awk -F "" '$9 != "-" {print $9}' | wc -l` -gt 0 ]; then
            VULN=1
        fi
    done

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_32(){
    echo "■ U-32. 홈 디렉토리로 지정한 디렉토리의 존재 관리" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우" >> $RESULT
    echo -e "[취약] : 홈 디렉토리가 존재하지 않는 계정이 발견된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VALUE=$(sudo cat /etc/passwd | awk -F ":" '$6 == "" {print $1}')
    VULN=0

    if [ -z "$VALUE" ]; then
        echo "홈 디렉토리가 존재하지 않는 계정이 발견되지 않았습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_33(){
    echo "■ U-33. 숨겨진 파일 및 디렉토리 검색 및 제거" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우" >> $RESULT
    echo -e "[취약] : 불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    echo "★ 숨겨진 파일 목록" >> $RESULT
    echo "" >> $RESULT
    sudo find / -type f -name ".*" 2>/dev/null | tail -20 >> $RESULT
    echo "" >> $RESULT
    echo "★ 숨겨진 디렉터리 목록" >> $RESULT
    echo "" >> $RESULT
    sudo find / -type d -name ".*" 2>/dev/null | tail -20 >> $RESULT

    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_34(){
    echo "■ U-34. Finger 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : Finger 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : Finger 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -i "in.fingerd" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "Finger 서비스가 비활성화 되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/finger 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/xinetd.d/finger | grep -i "disable" | grep -v "#" | awk -F " " '{print $3}' | tr '[:upper:]' '[:lower:]')
        if [ -z "$VALUE" ]; then
            VALUE=$(sudo cat /etc/xinetd.conf | sed -n '/defaults/,/}/p' | grep -i "finger" | grep -v "#")
            echo "$VALUE" >> $RESULT
            if [ `echo $VALUE | grep "enabled" | wc -l` -gt 0 ]; then
                VULN=1
            fi
        else
            sudo cat /etc/xinetd.d/finger | grep -i "disable" | grep -v "#" >> $RESULT
            if [ "$VALUE" != "yes" ]; then
                VULN=1
            fi
        fi
    else
        echo "Finger 서비스 설정 파일이 존재하지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_35(){
    echo "■ U-35. 공유 서비스에 대한 익명 접근 제한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 공유 서비스에 대해 익명 접근을 제한한 경우" >> $RESULT
    echo -e "[취약] : 공유 서비스에 대해 익명 접근을 허용한 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    
    FTP=$(sudo cat /etc/passwd | awk -F ":" '$1=="ftp"')
    echo "" >> $RESULT
    echo "★ FTP" >> $RESULT
    if [ -z "$FTP" ]; then
        echo "FTP 계정이 존재하지 않습니다." >> $RESULT
    else
        echo $FTP >> $RESULT
        ANONY_ENABLE=$(sudo cat /etc/passwd | awk -F ":" '$1=="anonymous"')
        if [ -n "$ANONY_ENABLE" ]; then
            VULN=1
        fi
    fi
    echo "" >> $RESULT
    echo "★ vsFTP" >> $RESULT
    vsFTP=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null)
    if [ -z "$vsFTP" ]; then
        echo "vsFTP 서비스를 사용하고 있지 않습니다." >> $RESULT
    else
        ANONY_ENABLE=$(sudo cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | grep anonymous_enable | grep -v "#")
        if [ -z "$ANONY_ENABLE" ]; then
            echo "vsFTP 서비스에 대해 익명 접근을 제한하고 있습니다." >> $RESULT
        else
            echo "$ANONY_ENABLE" >> $RESULT
            if [ `echo $ANONY_ENABLE | grep -i "yes" | wc -l` -gt 0 ]; then
                VULN=1
            fi
        fi
    fi
    echo "" >> $RESULT
    echo "★ ProFTP" >> $RESULT
    ProFTP=$(ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null)
    if [ -z "$ProFTP" ]; then
        echo "ProFTP 서비스를 사용하고 있지 않습니다." >> $RESULT
    else
        ANONY_ENABLE=$(sudo cat /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | sed -n '/<Anonymous ~ftp>/,/<\/Anonymous>/p')
        echo "$ANONY_ENABLE" >> $RESULT
        if [ `echo $ANONY_ENABLE | grep -v "#" | wc -l` -gt 0 ]; then
            VULN=1
        fi
    fi
    echo "" >> $RESULT
    echo "★ NFS" >> $RESULT
    NFS=$(ls /etc/export 2>/dev/null)
    if [ -z "$NFS" ]; then
        echo "NFS 서비스를 사용하고 있지 않습니다." >> $RESULT
    else
        ANONY_ENABLE=$(sudo cat /etc/exports | grep -E "anonuid|anongid")
        if [ -z "$ANONY_ENABLE" ]; then
            echo "NFS 서비스에 대해 익명 접근을 제한하고 있습니다." >> $RESULT
        else
            echo "$ANONY_ENABLE" >> $RESULT
            VULN=1
        fi
    fi
    echo "" >> $RESULT
    echo "★ Samba" >> $RESULT
    Samba=$(ls /etc/samba/smb.conf 2>/dev/null)
    if [ -z "$Samba" ]; then
        echo "Samba 서비스를 사용하고 있지 않습니다." >> $RESULT
    else
        ANONY_ENABLE=$(sudo cat /etc/samba/smb.conf | grep -i "guset ok")
        if [ -z "$ANONY_ENABLE" ]; then
            echo "Samba 서비스에 대해 익명 접근을 제한하고 있습니다." >> $RESULT
        else
            echo "$ANONY_ENABLE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_36(){
    echo "■ U-36. r 계열 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 불필요한 r 계열 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : 불필요한 r 계열 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -E "rsh|rlogin|rexec|rsync" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "r 계열 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/r* 2>/dev/null | wc -l` -gt 0 ]; then
        FILES=$(ls /etc/xinetd.d/ | grep -E 'rsh|rlogin|rexec')
        if [ -z "$FILES" ]; then
            echo "r 계열 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            for file in $FILES; do
                if [ `sudo cat /etc/xinetd.d/$file | grep -Ei "^[[:space:]]*[^#].*disable[[:space:]]*=[[:space:]]*no" | wc -l` -gt 0 ]; then
                    VULN=1
                fi
            done
        fi
    else
        VALUE=$(systemctl list-units --type=service | grep -E "rlogin|rsh|rexec")
        if [ -z "$VALUE" ]; then
            echo "r 계열 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_37(){
    echo "■ U-37. crontab 설정파일 권한 설정 미흡" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며,\ncron 및 at 관련 파일 권한이 640 이하인 경우" >> $RESULT
    echo -e "[취약] : crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며,\ncron 및 at 관련 파일 권한이 640 이상인 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0
    
    CRONTAB_PERM=$(ls -l /usr/bin/crontab 2>/dev/null | awk -F " " '{print $1}' | awk -F "" '{print $10}')
    AT_PERM=$(ls -l /usr/bin/at 2>/dev/null | awk -F " " '{print $1}' | awk -F "" '{print $10}')
    
    echo "★ /usr/bin/crontab 파일 권한" >> $RESULT
    if [ -z "$CRONTAB_PERM" ]; then
        echo "/usr/bin/crontab 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /usr/bin/crontab 2>/dev/null >> $RESULT
        if [ "$CRONTAB_PERM" != "-" ]; then
            VULN=1
        fi
    fi
    echo "" >> $RESULT
    echo "★ /usr/bin/at 파일 권한" >> $RESULT
    if [ -z "$AT_PERM" ]; then
        echo "/usr/bin/at 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /usr/bin/at 2>/dev/null >> $RESULT
        if [ "$AT_PERM" != "-" ]; then
            VULN=1
        fi
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    
    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 수동 진단" >> $RESULT
        echo "※ cron 및 at 관련 파일은 수동 진단하시길 바랍니다." >> $RESULT
        ((COUNT["SELF"]++))
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_38(){
    echo "■ U-38. DoS 공격에 취약한 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : DoS 공격에 취약한 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : DoS 공격에 취약한 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -E "echo|discard|daytime|chargen" | grep -v "#") 
        if [ -z "$VALUE" ]; then
            echo "DoS 공격에 취약한 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/ 2>/dev/null | grep -E "echo|discard|daytime|chargen" | wc -l` -gt 0 ]; then
        EXIST_FILE=$(ls /etc/xinetd.d/ 2>/dev/null | grep -E "echo|discard|daytime|chargen")
        if [ -z "$EXIST_FILE" ]; then
            echo "DoS 공격에 취약한 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            ENABLE_CHECK=$(sudo cat /etc/xinetd.conf | sed -n '/defaults/,/}/p' | grep -i "enabled" | grep -v "#")
            EXIST_DISABLE=$(echo $EXIST_FILE | grep -i "disable" | grep -v "#")
            if [ `echo $ENABLE_CHECK | grep -E "echo|discard|daytime|chargen" | wc -l` -gt 0 ]; then
                echo "$ENABLE_CHECK" >> $RESULT
                VULN=1
            else
                if [ `echo $EXIST_DISABLE | grep -i "no" | wc -l` -gt 0 ]; then
                    echo "$EXIST_DISABLE" >> $RESULT
                    VULN=1
                else
                    echo "DoS 공격에 취약한 서비스가 비활성화되어 있습니다." >> $RESULT
                fi
            fi
        fi
    else
        VALUE=$(systemctl list-units --type=service | grep -E "echo|discard|daytime|chargen")
        if [ -z "$VALUE" ]; then
            echo "DoS 공격에 취약한 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_39(){
    echo "■ U-39. 불필요한 NFS 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 불필요한 NFS 서비스 관련 데몬이 비활성화된 경우" >> $RESULT
    echo -e "[취약] : 불필요한 NFS 서비스 관련 데몬이 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(systemctl list-units --type=service | grep nfs)

    if [ -z "$VALUE" ]; then
        echo "NFS 서비스 관련 데몬이 비활성화되어 있습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_40(){
    echo "■ U-40. NFS 접근 통제" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우" >> $RESULT
    echo -e "[취약] : 접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    FILE_PERM=$(stat -c "%a" /etc/exports 2>/dev/null)
    if [ -z "$FILE_PERM" ]; then
        echo "/etc/exports 파일이 존재하지 않습니다." >> $RESULT
    else
        ls -l /etc/exports >> $RESULT
        echo "" >> $RESULT
        sudo cat /etc/exports 2>/dev/null >> $RESULT
    fi

    if [ "$FILE_PERM" -gt 644 ]; then
        VULN=1
    fi
    
    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_41(){
    echo "■ U-41. 불필요한 automountd 제거" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : automountd 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : automountd 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(systemctl list-units --type=service | grep -E "automount|autofs")
    if [ -z "$VALUE" ]; then
        echo "automountd 서비스가 비활성화되어 있습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_42(){
    echo "■ U-42. 불필요한 RPC 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 불필요한 RPC 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : 불필요한 RPC 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -i "rpc\.cmsd" | grep -v "#") 
        if [ -z "$VALUE" ]; then
            echo "불필요한 RPC 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/ 2>/dev/null | grep -i "rpc" | wc -l` -gt 0 ]; then
        EXIST_FILE=$(ls /etc/xinetd.d/ 2>/dev/null | grep -i "rpc")
        if [ -z "$EXIST_FILE" ]; then
            echo "불필요한 RPC 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            ENABLE_CHECK=$(sudo cat /etc/xinetd.conf | sed -n '/defaults/,/}/p' | grep -i "enabled" | grep -v "#")
            EXIST_DISABLE=$(echo $EXIST_FILE | grep -i "disable" | grep -v "#")
            if [ `echo $ENABLE_CHECK | grep -i "rpc" | wc -l` -gt 0 ]; then
                echo "$ENABLE_CHECK" >> $RESULT
                VULN=1
            else
                if [ `echo $EXIST_DISABLE | grep -i "no" | wc -l` -gt 0 ]; then
                    echo "$EXIST_DISABLE" >> $RESULT
                    VULN=1
                else
                    echo "불필요한 RPC 서비스가 비활성화되어 있습니다." >> $RESULT
                fi
            fi
        fi
    else
        VALUE=$(systemctl list-units --type=service | grep rpc)
        if [ -z "$VALUE" ]; then
            echo "불필요한 RPC 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_43(){
    echo "■ U-43. NIS, NIS+ 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우" >> $RESULT
    echo -e "[취약] : NIS 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(systemctl list-units --type=service | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated")

    if [ -z "$VALUE" ]; then
        echo "NIS 서비스가 비활성화되어 있습니다." >> $RESULT
    else
        echo "$VALUE" >> $RESULT
        if [ `systemctl status nisplus 2>/dev/null | wc -l` -lt 1 ]; then
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_44(){
    echo "■ U-44. tftp, talk 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : tftp, talk, ntalk 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : tftp, talk, ntalk 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -E "tftp|talk|ntalk" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "tftp, talk, ntalk 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/ 2>/dev/null | wc -l` -gt 0 ]; then
        EXIST_FILE=$(ls /etc/xinetd.d/ | grep -E "tftp|talk|ntalk")
        if [ -z "$EXIST_FILE" ]; then
            echo "tftp, talk, ntalk 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            ENABLE_CHECK=$(sudo cat /etc/xinetd.conf | sed -n '/defaults/,/}/p' | grep -i "enabled" | grep -v "#")
            EXIST_DISABLE=$(echo $EXIST_FILE | grep -i "disable" | grep -v "#")
            if [ `echo $ENABLE_CHECK | grep -E "tftp|talk|ntalk" | wc -l` -gt 0 ]; then
                echo "$ENABLE_CHECK" >> $RESULT
                VULN=1
            else
                if [ `echo $EXIST_DISABLE | grep -i "no" | wc -l` -gt 0 ]; then
                    echo "$EXIST_DISABLE" >> $RESULT
                    VULN=1
                else
                    echo "tftp, talk, ntalk 서비스가 비활성화되어 있습니다." >> $RESULT
                fi
            fi
        fi
    else
        VALUE=$(systemctl list-units --type=service | grep -E "tftp|talk|ntalk")
        if [ -z "$VALUE" ]; then
            echo "tftp, talk, ntalk 서비스가 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_45(){
    echo "■ U-45. 메일 서비스 버전 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 메일 서비스 버전이 최신 버전인 경우" >> $RESULT
    echo -e "[취약] : 메일 서비스 버전이 최신 버전이 아닌 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    if [ `systemctl is-active sendmail` == "active" ]; then
        timeout 2s sendmail -d0 -bt < /dev/null >> $RESULT
    elif [ `postconf mail_version 2>/dev/null | wc -l` -gt 0 ]; then
        postconf mail_version >> $RESULT
    elif [ `systemctl list-units --type=service | grep "exim" | wc -l` -gt 0 ]; then
        echo "https://www.exim.org/에 접속하여 최신 버전 확인 및 보안 패치를 진행하시길 바랍니다." >> $RESULT
    else
        echo "메일 서비스를 사용하고 있지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_46(){
    echo "■ U-46. 일반 사용자의 메일 서비스 실행 방지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 일반 사용자의 메일 서비스 실행 방지가 설정된 경우" >> $RESULT
    echo -e "[취약] : 일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/mail/sendmail.cf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/mail/sendmail.cf | grep -i "restrictqrun" | grep -v "#" | wc -l)
        sudo cat /etc/mail/sendmail.cf | grep -i "PrivacyOptions" | grep -v "#" >> $RESULT
        if [ $VALUE -lt 1 ]; then
            VULN=1
        fi
    elif [ `ls -l /usr/sbin/postsuper 2>/dev/null | wc -l` -gt 0 ]; then
        ls -l /usr/sbin/postsuper >> $RESULT
        VALUE=$(ls -l /usr/sbin/postsuper | awk -F " " '{print $1}' | awk -F "" '{print $10}')
        if [ "$VALUE" == "x" ]; then
            VULN=1
        fi
    elif [ `ls ls -l /usr/sbin/exiqgrep 2>/dev/null | wc -l` -gt 0 ]; then
        ls -l /usr/sbin/exiqgrep >> $RESULT
        VALUE=$(ls -l /usr/sbin/exiqgrep | awk -F " " '{print $1}' | awk -F "" '{print $10}')
        if [ "$VALUE" == "x" ]; then
            VULN=1
        fi
    else
        echo "메일 서비스가 설치되어 있지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_47(){
    echo "■ U-47. 스팸 메일 릴레이 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 릴레이 제한이 설정된 경우" >> $RESULT
    echo -e "[취약] : 릴레이 제한이 설정되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    MTA_TYPE="None"
    if [ -f /usr/lib/sendmail ] || [ -f /usr/sbin/sendmail ]; then
        if postconf -n >/dev/null 2>&1; then
            MTA_TYPE="Postfix"
        else
            MTA_TYPE="Sendmail"
        fi
    elif [ -f /usr/sbin/exim ]; then
        MTA_TYPE="Exim"
    fi

    if [ "$MTA_TYPE" == "None" ]; then
        echo "메일 서비스가 설치되어 있지 않습니다." >> $RESULT
    else
        if [ "$MTA_TYPE" == "Sendmail" ] && [ `ls /etc/mail/sendmail.mc 2>/dev/null | wc -l` -gt 0 ]; then
            VALUE=$(sudo cat /etc/mail/sendmail.mc | grep "promiscuous_relay" | grep -v "#" | wc -l)
            if [ $VALUE -gt 0 ]; then
                VULN=1
                echo "$VALUE" >> $RESULT
            else
                echo "/etc/mail/sendmail.mc 파일 내 promiscuous_relay 설정이 존재하지 않습니다." >> $RESULT
            fi
        elif [ "$MTA_TYPE" == "Sendmail" ] && [ `ls /etc/mail/sendmail.cf 2>/dev/null | wc -l` -gt 0 ]; then
            VALUE=$(sudo cat /etc/mail/sendmail.cf | grep -v "#" | grep "R$\*" | grep "Relaying denied")
            if [ -z "$VALUE" ]; then
                VULN=1
                echo "/etc/mail/sendmail.cf 파일 내 Relaying denied 설정이 존재하지 않습니다." >> $RESULT  
            else
                echo "$VALUE" >> $RESULT    
            fi
        elif [ "$MTA_TYPE" == "Postfix" ]; then
            VALUE=$(sudo cat /etc/postfix/main.cf | grep -v "#" | grep -E "smtpd_recipient_restrictions|mynetworks")
            if [ -z "$VALUE" ]; then
                VULN=1
                echo -e "/etc/postfix/main.cf 파일 내 smtpd_recipient_restrictions\nmynetworks 설정이 존재하지 않습니다." >> $RESULT  
            else
                echo "$VALUE" >> $RESULT    
            fi
        else
            VALUE=$(sudo cat /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null | grep -v "#" | grep -E "relay_from_hosts|hosts =")
            if [ -z "$VALUE" ]; then
                VULN=1
                echo -e "릴레이 제한 설정이 존재하지 않습니다." >> $RESULT  
            else
                echo "$VALUE" >> $RESULT    
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_48(){
    echo "■ U-48. expn, vrfy 명령어 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : noexpn, novrfy 옵션이 설정된 경우" >> $RESULT
    echo -e "[취약] : noexpn, novrfy 옵션이 설정되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    MTA_TYPE="None"
    if [ -f /usr/lib/sendmail ] || [ -f /usr/sbin/sendmail ]; then
        if postconf -n >/dev/null 2>&1; then
            MTA_TYPE="Postfix"
        else
            MTA_TYPE="Sendmail"
        fi
    elif [ -f /usr/sbin/exim ]; then
        MTA_TYPE="Exim"
    fi

    if [ "$MTA_TYPE" == "None" ]; then
        echo "메일 서비스가 설치되어 있지 않습니다." >> $RESULT
    else
        if [ "$MTA_TYPE" == "Sendmail" ]; then
            OPTIONS=$(sudo cat /etc/mail/sendmail.cf 2>/dev/null | grep -i "PrivacyOptions" | grep -v "#")
            if [[ `echo $OPTIONS | grep -E "noexpn.*novrfy|novrfy.*noexpn" | wc -l` -lt 1 ]] && [[ `echo $OPTIONS | grep "goaway" | wc -l` -lt 1 ]]; then
                VULN=1
                echo "/etc/mail/sendmail.cf 파일 내 noexpn, novrfy 옵션이 설정되어 있지 않습니다." >> $RESULT
            else
                echo "$OPTIONS" >> $RESULT
            fi
        elif [ "$MTA_TYPE" == "Postfix" ]; then
            OPTIONS=$(sudo cat /etc/postfix/main.cf 2>/dev/null | grep -i "disable_vrfy_command" | grep -v "#")
            if [ `echo $OPTIONS | grep -i "yes" | wc -l` -lt 1 ]; then
                VULN=1
                echo "/etc/postfix/main.cf 파일 내 noexpn, novrfy 옵션이 설정되어 있지 않습니다." >> $RESULT
            else
                echo "$OPTIONS" >> $RESULT
            fi
        else
            OPTIONS=$(sudo cat /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null | grep -E "expn|vrfy" | grep -v "#")
            if [ -z "$OPTIONS" ]; then
                echo "/etc/exim/exim.conf, /etc/exim4/exim4.conf 파일 내 noexpn, novrfy 옵션이 설정되어 있지 않습니다." >> $RESULT
                VULN=1
            else
                "$OPTIONS" >> $RESULT
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_49(){
    echo "■ U-49. DNS 보안 버전 패치" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 주기적으로 패치를 관리하는 경우" >> $RESULT
    echo -e "[취약] : 주기적으로 패치를 관리하고 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `named -v 2>/dev/null | wc -l` -lt 1 ]; then
        echo "DNS 서비스가 설치되어 있지 않습니다." >> $RESULT
        echo "" >> $RESULT
        echo "" >> $RESULT
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    else
        named -v >> $RESULT
        echo "" >> $RESULT
        echo "" >> $RESULT
        echo "※ 점검 결과: 수동 진단" >> $RESULT
        ((COUNT["SELF"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_50(){
    echo "■ U-50. DNS ZoneTransfer 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : Zone Transfer를 허가된 사용자에게만 허용한 경우" >> $RESULT
    echo -e "[취약] : Zone Transfer를 모든 사용자에게 허용한 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    EXIST_DNS=$(named -v 2>/dev/null)
    if [ -n "$EXIST_DNS" ]; then
        if [ `ls /etc/named.conf 2>/dev/null | wc -l` -gt 0 ]; then
            VALUE=$(sudo cat /etc/named.conf | grep allow-transfer | grep -v "#")
            if [ -z "$VALUE" ]; then
                VULN=1
                echo "allow-transfer 설정이 존재하지 않습니다." >> $RESULT
            else
                echp "$VALUE" >> $RESULT
            fi
        elif [ `ls /etc/bind/named.conf.options 2>/dev/null | wc -l` -gt 0 ]; then
            VALUE=$(sudo cat /etc/bind/named.conf.options | grep allow-transfer | grep -v "#")
            if [ -z "$VALUE" ]; then
                VULN=1
                echo "allow-transfer 설정이 존재하지 않습니다." >> $RESULT
            else
                echp "$VALUE" >> $RESULT
            fi
        fi
    else
        echo "DNS 서비스가 설치되어 있지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_51(){
    echo "■ U-51. DNS 서비스의 취약한 동적 업데이트 설정 금지" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우" >> $RESULT
    echo -e "[취약] : DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근통제를 수행하고 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    EXIST_DNS=$(named -v 2>/dev/null)
    if [ -n "$EXIST_DNS" ]; then
        ALLOW_UPDATE=$(sudo cat /etc/named.conf /etc/bind/named.conf.options 2>/dev/null | grep -i "allow-update")
        echo "$ALLOW_UPDATE" >> $RESULT
    else
        echo "DNS 서비스가 설치되어 있지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_52(){
    echo "■ U-52. Telnet 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우" >> $RESULT
    echo -e "[취약] : 원격 접속 시 Telnet 프로토콜을 사용하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/inetd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/inetd.conf | grep -i "Telnet" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "Telnet 프로토콜이 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    elif [ `ls /etc/xinetd.d/telnet 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/xinetd.d/telnet | grep -i "disable" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "Telnet 프로토콜이 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            if [ `echo $VALUE | grep -i "yes" | wc -l` -lt 1 ]; then
                VULN=1
            fi
        fi
    else
        VALUE=$(systemctl list-units --type=socket | grep "telnet")
        if [ -z "$VALUE" ]; then
            echo "Telnet 프로토콜이 비활성화되어 있습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_53(){
    echo "■ U-53. FTP 서비스 정보 노출 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : FTP 접속 배너에 노출되는 정보가 없는 경우" >> $RESULT
    echo -e "[취약] : FTP 접속 배너에 노출되는 정보가 있는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/vsftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/vsftpd.conf | grep "ftpd_banner" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "/etc/vsftpd.conf 파일 내 ftpd_banner 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/vsftpd/vsftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/vsftpd/vsftpd.conf | grep "ftpd_banner" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "/etc/vsftpd/vsftpd.conf 파일 내 ftpd_banner 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/proftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/proftpd.conf | grep "ServerIdent" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "/etc/proftpd.conf 파일 내 ServerIdent 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/proftpd/proftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/proftpd/proftpd.conf | grep "ServerIdent" | grep -v "#")
        if [ -z "$VALUE" ]; then
            echo "/etc/proftpd/proftpd.conf 파일 내 ServerIdent 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    else
        echo "vsFTP, ProFTP 설정 파일이 존재하지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_54(){
    echo "■ U-54. 암호화되지 않는 FTP 서비스 비활성화" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 암호화되지 않은 FTP 서비스가 비활성화된 경우" >> $RESULT
    echo -e "[취약] : 암호화되지 않은 FTP 서비스가 활성화된 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `sudo cat /etc/inetd.conf 2>/dev/null | grep -v "#" | grep "ftp" | grep "in.ftpd" | wc -l` -gt 0 ]; then
        sudo cat /etc/inetd.conf | grep -v "#" | grep "ftp" | grep "in.ftpd" >> $RESULT
        VULN=1
    elif [ `sudo cat /etc/xinetd.d/ftp 2>/dev/null | grep -v "#" | grep -i "disable" | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/xinetd.d/ftp | grep -v "#" | grep -i "disable")
        if [ -z "$VALUE" ]; then
            ENABLE_CHECK=$(sudo cat /etc/xinetd.conf | sed -n '/defaults/,/}/p' | grep -i "enabled" | grep -v "#")
            if [ `echo $ENABLE_CHECK | grep -i "ftp" | wc -l` -gt 0 ]; then
                echo "$ENABLE_CHECK" >> $RESULT
                VULN=1
            else
                if [ `echo $VALUE | grep -i "no" | wc -l` -gt 0 ]; then
                    echo "$VALUE" >> $RESULT
                    VULN=1
                fi
            fi
        else
            echo "$VALUE" >> $RESULT
            if [ `echo $VALUE | grep -i "yes" | wc -l` -lt 1 ]; then
                VULN=1
            fi
        fi
    elif [ `systemctl list-units --type=service | grep "vsftpd" | wc -l` -gt 0 ]; then
        systemctl list-units --type=service | grep "vsftpd" >> $RESULT
        VULN=1
    elif [ `systemctl list-units --type=service | grep "proftp" | wc -l` -gt 0 ]; then
        systemctl list-units --type=service | grep "proftp" >> $RESULT
        VULN=1
    else
        echo "FTP 서비스가 비활성화되어 있습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_55(){
    echo "■ U-55. FTP 계정 shell 제한" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우" >> $RESULT
    echo -e "[취약] : FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    FTP_ACCOUNT=$(sudo cat /etc/passwd | grep "ftp")
    if [ -z "$FTP_ACCOUNT" ]; then
        echo "시스템 내 FTP 계정이 존재하지 않습니다." >> $RESULT
    else
        echo "$FTP_ACCOUNT" >> $RESULT
        VALUE=$(echo $FTP_ACCOUNT | awk -F ":" '{print $7}')
        if [[ "$VALUE" != "/bin/false" ]] && [[ "$VALUE" != "/sbin/nologin" ]] && [[ "$VALUE" != "/usr/sbin/nologin" ]]; then
            VULN=1
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_56(){
    echo "■ U-56. FTP 서비스 접근 제어 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록\n접근 제어 설정을 적용한 경우" >> $RESULT
    echo -e "[취약] : FTP 서버에 접근 제어 설정을 적용하지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/ftpusers 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/ftpusers)
        if [ -z "$VALUE" ]; then
            echo "/etc/ftpusers 파일 내 접근 제어 설정이 적용되어 있지 않습니다." >> $RESULT
            VULN=1
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        echo "★ /etc/vsftpd.conf(/etc/vsftpd/vsftpd.conf) 파일 내 userlist_enable 설정 확인" >> $RESULT
        FTP_USERS=$(sudo cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | grep -i "userlist_enable" | grep -v "#")
        if [ -z "$FTP_USERS" ]; then
            echo "/etc/vsftpd.conf(/etc/vsftpd/vsftpd.conf) 파일 내 userlist_enable 설정이 존재하지 않습니다." >> $RESULT
            VULN=1
        else
            echo "$FTP_USERS" >> $RESULT
            ENABLE_CHECK=$(echo $FTP_USERS | awk -F= '/^[[:space:]]*userlist_enable[[:space:]]*=/ {gsub(/ /,"",$2); print $2}' | tr '[:upper:]' '[:lower:]')
            if [ $ENABLE_CHECK == "no" ]; then
                VULN=1
            fi
        fi
        echo "" >> $RESULT
        if [ `ls /etc/vsftpd.ftpusers 2>/dev/null | wc -l` -gt 0 ]; then
            echo "★ /etc/vsftpd.ftpusers 파일 내 접근 제한 설정 확인" >> $RESULT
            sudo cat /etc/vsftpd.ftpusers >> $RESULT
        elif [ `ls /etc/vsftpd.user_list 2>/dev/null | wc -l` -gt 0 ]; then
            echo "★ /etc/vsftpd.user_list 파일 내 접근 제한 설정 확인" >> $RESULT
            sudo cat /etc/vsftpd.user_list >> $RESULT
        elif [ `ls /etc/vsftpd/user_list 2>/dev/null | wc -l` -gt 0 ]; then
            echo "★ /etc/vsftpd/user_list 파일 내 접근 제한 설정 확인" >> $RESULT
            sudo cat /etc/vsftpd/user_list >> $RESULT
        fi
    elif [[ `ls /etc/proftpd.conf 2>/dev/null | wc -l` -gt 0 ]]|| [[ `ls /etc/proftpd/proftpd.conf 2>/dev/null | wc -l` -gt 0 ]]; then
        echo "★ /etc/proftpd.conf(/etc/proftpd/proftpd.conf) 파일 내 UseFtpUsers 설정 확인" >> $RESULT
        VALUE=$(sudo cat /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | grep "UseFtpUsers" | grep -v "#")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "UseFtpUsers 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            if [ `echo $VALUE | grep -i "on" | wc -l` -lt 1 ]; then
                VULN=1
            fi
        fi
        echo "" >> $RESULT
        if [[ `ls /etc/ftpusers 2>/dev/null | wc -l` -gt 0 ]] || [[ `ls /etc/ftpd/ftpusers 2>/dev/null | wc -l` -gt 0 ]]; then
            echo "★ ftpusers 파일 확인" >> $RESULT
            sudo cat /etc/ftpusers /etc/ftpd/ftpusers 2>/dev/null >> $RESULT
        fi
        if [[ -n `sed -n '/<Limit LOGIN>/, /<\/Limit>/p' /etc/proftpd.conf` ]] || [[ `sed -n '/<Limit LOGIN>/, /<\/Limit>/p' /etc/proftpd/proftpd.conf` ]]; then
            echo "★ /etc/proftpd.conf(/etc/proftpd/proftpd.conf) 파일 내 접근 제한 설정 확인" >> $RESULT
            sed -n '/<Limit LOGIN>/, /<\/Limit>/p' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null >> $RESULT
        fi
    else
        echo "FTP 서비스 접근 제어 설정 파일이 존재하지 않습니다." >> $RESULT
    fi
    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_57(){
    echo "■ U-57. Ftpusers 파일 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : root 계정 접속을 차단한 경우" >> $RESULT
    echo -e "[취약] : root 계정 접속을 허용한 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    if [ `ls /etc/ftpusers 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/ftpusers | grep -v "#" | grep -i "root")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "root 계정 접속 차단 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/ftpd/ftpusers 2>/dev/null | wc -l` -gt 0 ]; then
        VALUE=$(sudo cat /etc/ftpd/ftpusers | grep -v "#" | grep -i "root")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "root 계정 접속 차단 설정이 존재하지 않습니다." >> $RESULT
        else
            echo "$VALUE" >> $RESULT
        fi
    elif [ `ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | wc -l` -gt 0 ]; then
        FTP_USERS=$(sudo cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null | grep -i "userlist_enable" | grep -v "#")
        echo "★ /etc/vsftpd.conf(/etc/vsftpd/vsftpd.conf) 파일 내 userlist_enable 설정 확인" >> $RESULT
        if [ -z "$FTP_USERS" ]; then
            echo "/etc/vsftpd.conf 파일 내 userlist_enable 설정이 존재하지 않습니다." >> $RESULT
            echo "" >> $RESULT
            VULN=1
        else
            echo "$FTP_USERS" >> $RESULT
            echo "" >> $RESULT
            ENABLE_CHECK=$(echo $FTP_USERS | awk -F= '/^[[:space:]]*userlist_enable[[:space:]]*=/ {gsub(/ /,"",$2); print $2}' | tr '[:upper:]' '[:lower:]')
            if [ $ENABLE_CHECK == "no" ]; then
                VULN=1
            fi
            echo "★ root 계정 접속 차단 설정 확인" >> $RESULT
            if [ `ls /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null | wc -l` -gt 0 ]; then
                VALUE=$(sudo cat /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null | grep -v "#" | grep -i "root")
                if [ -z "$VALUE" ]; then
                    echo "root 계정 접속 차단 설정이 존재하지 않습니다." >> $RESULT
                    VULN=1
                else
                    echo "$VALUE" >> $RESULT
                fi
            elif [ `ls /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null | wc -l` -gt 0 ]; then
                VALUE=$(sudo cat /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null | grep -v "#" | grep -i "root")
                if [ -z "$VALUE" ]; then
                    echo "root 계정 접속 차단 설정이 존재하지 않습니다." >> $RESULT
                    VULN=1
                else
                    echo "$VALUE" >> $RESULT
                fi
            fi
        fi
    else
        echo "Ftpusers 파일이 존재하지 않습니다." >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_58(){
    echo "■ U-58. 불필요한 SNMP 서비스 구동 점검" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : SNMP 서비스를 사용하지 않는 경우" >> $RESULT
    echo -e "[취약] : SNMP 서비스를 사용하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(systemctl list-units --type=service | grep -i "snmpd")
    if [ -z "$VALUE" ]; then
        echo "SNMP 서비스가 비활성화되어 있습니다."  >> $RESULT
    else
        echo "$VALUE"  >> $RESULT
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_59(){
    echo "■ U-59. 안전한 SNMP 버전 사용" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : SNMP 서비스를 v3 이상으로 사용하는 경우" >> $RESULT
    echo -e "[취약] : SNMP 서비스를 v2 이하로 사용하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    SNMP_VERSION=$(snmpwalk -V 2>/dev/null | awk '{print $3}')
    
    if [ -z "$SNMP_VERSION" ]; then
        echo "SNMP 서비스가 설치되어 있지 않습니다." >> $RESULT
    else
        V3_CHECK=$(sudo grep -v '^#' /etc/snmp/snmpd.conf 2>/dev/null | grep -Ei "rouser|rwuser|createUser")
        if [ -n "$V3_CHECK" ]; then
            echo "$V3_CHECK" | sed 's/^/  - /' >> $RESULT
        else
            VULN=1
            V2_CHECK=$(sudo grep -v '^#' /etc/snmp/snmpd.conf 2>/dev/null | grep "community")
            if [ -n "$V2_CHECK" ]; then
                echo "$V2_CHECK" >> $RESULT
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_60(){
    echo "■ U-60. SNMP Community String 복잡성 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : SNMP Community String 기본값인 "public", "private"이 아닌 영문자,\n숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우" >> $RESULT
    echo -e "※ SNMP v3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡도를 만족하는 경우 양호" >> $RESULT
    echo "" >> $RESULT
    echo -e "[취약] : 아래의 내용 중 하나라도 해당되는 경우" >> $RESULT
    echo "1. SNMP Community String 기본값인 "public", "private"일 경우" >> $RESULT
    echo "2. 영문자, 숫자 포함 10자리 미만인 경우" >> $RESULT
    echo "3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    SNMP_VERSION=$(snmpwalk -V 2>/dev/null | awk '{print $3}')
    CONF_FILE="/etc/snmp/snmpd.conf"
    
    if [ -z "$SNMP_VERSION" ]; then
        echo "SNMP 서비스가 설치되어 있지 않습니다." >> $RESULT
    elif [ ! -f "$CONF_FILE" ]; then
        echo "오류: $CONF_FILE 파일을 찾을 수 없습니다." >> $RESULT
        return 1
    else
        if [ `echo $OS_TYPE | tr '[:upper:]' '[:lower:]'` == "redhat" ]; then
            COMMUNITIES=$(sudo grep -v '^#' "$CONF_FILE" | grep -i "com2sec" | awk '{print $2}')
            if [ -n "$COMMUNITIES" ]; then
                sudo cat $CONF_FILE | grep -i "com2sec" | grep -v "#" >> $RESULT
                for STR in $COMMUNITIES; do
                    LEN=${#STR}
                    HAS_ALPHA=$(echo "$STR" | grep -q '[a-zA-Z]' && echo "yes" || echo "no")
                    HAS_NUM=$(echo "$STR" | grep -q '[0-9]' && echo "yes" || echo "no")
                    HAS_SPECIAL=$(echo "$STR" | grep -q '[[ :punct: ]]' && echo 1 || echo 0)

                    # 영문, 숫자 포함 10자리 미만 확인
                    if [ $((HAS_ALPHA + HAS_NUM)) -ge 2 ] && [ $LEN -lt 10 ]; then
                        VULN=1
                    fi

                    # 영문, 숫자, 특수문자 포함 8자리 미만 확인
                    if [ $((HAS_ALPHA + HAS_NUM + HAS_SPECIAL)) -eq 3 ] && [ $LEN -lt 8 ]; then
                        VULN=1
                    fi

                    # 기본 보안 검사 (조합 자체가 안된 경우 추가)
                    if [ $((HAS_ALPHA + HAS_NUM)) -lt 2 ]; then
                        VULN=1
                    fi
                done
            else
                echo "SNMP Community String이 활성화되어 있지 않습니다." >> $RESULT
            fi
        elif [ `echo $OS_TYPE | tr '[:upper:]' '[:lower:]'` == "debian" ]; then
            COMMUNITIES=$(sudo grep -v '^#' "$CONF_FILE" | grep -iE "rocommunity|rwcommunity" | awk '{print $2}')
            if [ -n "$COMMUNITIES" ]; then
                sudo cat $CONF_FILE | grep -iE "rocommunity|rwcommunity" | grep -v "#" >> $RESULT
                for STR in $COMMUNITIES; do
                    LEN=${#STR}
                    HAS_ALPHA=$(echo "$STR" | grep -q '[a-zA-Z]' && echo "yes" || echo "no")
                    HAS_NUM=$(echo "$STR" | grep -q '[0-9]' && echo "yes" || echo "no")
                    HAS_SPECIAL=$(echo "$STR" | grep -q '[[ :punct: ]]' && echo 1 || echo 0)

                    # 영문, 숫자 포함 10자리 미만 확인
                    if [ $((HAS_ALPHA + HAS_NUM)) -ge 2 ] && [ $LEN -lt 10 ]; then
                        VULN=1
                    fi

                    # 영문, 숫자, 특수문자 포함 8자리 미만 확인
                    if [ $((HAS_ALPHA + HAS_NUM + HAS_SPECIAL)) -eq 3 ] && [ $LEN -lt 8 ]; then
                        VULN=1
                    fi

                    # 기본 보안 검사 (조합 자체가 안된 경우 추가)
                    if [ $((HAS_ALPHA + HAS_NUM)) -lt 2 ]; then
                        VULN=1
                    fi
                done
            else
                echo "SNMP Community String이 활성화되어 있지 않습니다." >> $RESULT
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_61(){
    echo "■ U-61. SNMP Access Control 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : SNMP 서비스에 접근 제어 설정이 되어 있는 경우" >> $RESULT
    echo -e "[취약] : SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    SNMP_VERSION=$(snmpwalk -V 2>/dev/null | awk '{print $3}')
    CONF_FILE="/etc/snmp/snmpd.conf"
    if [ -z "$SNMP_VERSION" ]; then
        echo "SNMP 서비스가 설치되어 있지 않습니다." >> $RESULT
    elif [ ! -f "$CONF_FILE" ]; then
        echo "오류: $CONF_FILE 파일을 찾을 수 없습니다." >> $RESULT
        return 1
    else
        if [ "$OS_TYPE" == "redhat" ]; then
            COM2SEC_NAME=$(sudo cat $CONF_FILE | grep -i "com2sec" | grep -v "#" | awk '$1 == "com2sec" {print $2}')
            GROUP_SEC_NAME=$(sudo cat $CONF_FILE | grep -i "group" | grep -v "#" | awk '$1 == "group" {print $4}')
            GROUP_NAME=$(sudo cat $CONF_FILE | grep -v "#" | grep "$GROUP_SEC_NAME" | awk '$1 == "group" {print $2}')
            ACCESS_GROUP=$(sudo cat $CONF_FILE | grep -i "access" | grep -v "#" | awk '$1 == "access" {print $2}')
            sudo cat $CONF_FILE | grep -v "#" | grep -Ei "com2sec|group|access" >> $RESULT
            if [ -z "$COM2SEC_NAME" ] || [ -z "$GROUP_SEC_NAME" ] || [ -z "$GROUP_NAME" ] || [ -z "$ACCESS_GROUP" ]; then
                VULN=1
            elif [ "$COM2SEC_NAME" != "$GROUP_SEC_NAME" ]; then
                VULN=1
            elif [ "$GROUP_NAME" != "$ACCESS_GROUP" ]; then
                VULN=1
            fi
        else
            CHECK_VALUE=$(sudo cat $CONF_FILE | grep -Ei "rocommunity|rwcommunity|com2sec|community" | grep -v "#")
            if [ -n "$CHECK_VALUE" ]; then
                echo "$CHECK_VALUE" >> $RESULT
                VULN=1
            else
                echo "SNMP v1/v2c 설정이 존재하지 않습니다." >> $RESULT
            fi
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_62(){
    echo "■ U-62. 로그인 시 경고 메시지 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시\n경고 메시지가 설정된 경우" >> $RESULT
    echo -e "[취약] : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시\n경고 메시지가 설정되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    SERVER_FILE=$(ls /etc/motd /etc/issue 2>/dev/null)
    TELNET_FILE=$(ls /etc/issue.net 2>/dev/null)
    SSH_FILE=$(ls /etc/ssh/sshd_config 2>/dev/null)
    SENDMAIL_FILE=$(ls /etc/mail/sendmail.cf 2>/dev/null)
    POSTFIX_FILE=$(ls /etc/postfix/main.cf 2>/dev/null)
    EXIM_FILE=$(ls /exim/exim.conf /exim4/exim4.conf 2>/dev/null)
    VSFTP_FILE=$(ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null)
    PROFTP_FILE=$(ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null)
    DNS_FILE=$(ls /etc/named.conf /etc/bind/named.conf.options 2>/dev/null)

    if [ -f "$SERVER_FILE" ]; then
        echo "★ 서버" >> $RESULT
        VALUE=$(sudo cat $SERVER_FILE | grep -v "#" | grep -Ei "warning|unauthorized|security|access")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> 서버 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$TELNET_FILE" ]; then
        echo "★ TELNET" >> $RESULT
        VALUE=$(sudo cat $TELNET_FILE | grep -v "#" | grep -Ei "warning|unauthorized|security|access")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> TELNET 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$SSH_FILE" ]; then
        echo "★ SSH" >> $RESULT
        VALUE=$(sudo cat $SSH_FILE | grep -i "Banner" | grep -v "#")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> SSH 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$SENDMAIL_FILE" ]; then
        echo "★ Sendmail" >> $RESULT
        VALUE=$(sudo cat $SENDMAIL_FILE | grep -v "#" | grep -i "SmtpGreetingMessage")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> Sendmail 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$POSTFIX_FILE" ]; then
        echo "★ Postfix" >> $RESULT
        VALUE=$(sudo cat $POSTFIX_FILE | grep -v "#" | grep -i "smtpd_banner")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> Postfix 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$EXIM_FILE" ]; then
        echo "★ Exim" >> $RESULT
        VALUE=$(sudo cat $EXIM_FILE | grep -v "#" | grep -i "smtp_banner")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> Exim 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$VSFTP_FILE" ]; then
        echo "★ vsFTP" >> $RESULT
        VALUE=$(sudo cat $VSFTP_FILE | grep -v "#" | grep -i "ftpd_banner")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> vsFTP 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$PROFTP_FILE" ]; then
        echo "★ ProFTP" >> $RESULT
        VALUE=$(sudo cat $PROFTP_FILE | grep -v "#" | grep -i "DisplayLogin")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> ProFTP 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi
    if [ -f "$DNS_FILE" ]; then
        echo "★ DNS" >> $RESULT
        VALUE=$(sudo cat $DNS_FILE | grep -v "#" | grep -i "version")
        if [ -z "$VALUE" ]; then
            VULN=1
            echo "-> DNS 서비스 로그온 시 경고 메시지가 설정되어 있지 않습니다." >> $RESULT
            echo "" >> $RESULT
        else
            echo "$VALUE" >> $RESULT
            echo "" >> $RESULT
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_63(){
    echo "■ U-63. sudo 명령어 접근 관리" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우" >> $RESULT
    echo -e "[취약] : /etc/sudoers 파일 소유자가 root가 아니거나,\n파일 권한이 640을 초과하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    ls -l /etc/sudoers >> $RESULT
    FILE_OWNER=$(ls -l /etc/sudoers | awk -F " " '{print $3}')
    FILE_PERM=$(stat -c "%a" /etc/sudoers)
    
    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 640 ]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_64(){
    echo "■ U-64. 주기적 보안 패치 및 벤더 권고사항 적용" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며,\n패치 관련 내용을 확인하고 적용하였을 경우" >> $RESULT
    echo -e "[취약] : 패치 적용 정책을 수립하지 않고 주기적으로 패치 관리를 하지 않거나,\n패치 관련 내용을 확인하지 않고 적용하지 않고 있는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    hostnamectl >> $RESULT
    
    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_65(){
    echo "■ U-65. NTP 및 시각 동기화 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우" >> $RESULT
    echo -e "[취약] : NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT

    NTP=$(systemctl list-units --type=service | grep ntp)
    CHRONY=$(systemctl list-units --type=service | grep chrony)
    if [ -n "$NTP" ]; then
        echo "★ NTP" >> $RESULT
        ntpq -pn >> $RESULT
    else
        if [ -n "$CHRONY" ]; then
            echo "★ Chrony" >> $RESULT
            chronyc sources >> $RESULT
        else
            echo "NTP/Chrony 서비스가 비활성화되어 있습니다." >> $RESULT
        fi
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT
    echo "※ 점검 결과: 수동 진단" >> $RESULT
    ((COUNT["SELF"]++))

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_66(){
    echo "■ U-66. 정책에 따른 시스템 로깅 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며,\n로그를 남기고 있는 경우" >> $RESULT
    echo -e "[취약] : 로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나,\n로그를 남기고 있지 않은 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VALUE=$(sudo cat /etc/rsyslog.conf /etc/rsyslog.d/default.conf 2>/dev/null | grep -v "#")
    if [ -z "$VALUE" ]; then
        echo "로그 기록 정책이 미수립되어 있습니다." >> $RESULT
        VULN=1
    else
        echo "$VALUE" | tr -s '\n' >> $RESULT
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 수동 진단" >> $RESULT
        ((COUNT["SELF"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}
U_67(){
    echo "■ U-67. 로그 디렉터리 소유자 및 권한 설정" >> $RESULT
    echo "" >> $RESULT
    echo -e "[양호] : 디렉터리 내 로그 파일의 소유자가 root이고,/n권한이 644 이하인 경우" >> $RESULT
    echo -e "[취약] : 디렉터리 내 로그 파일의 소유자가 root가 아니거나,\n권한이 644를 초과하는 경우" >> $RESULT
    echo "" >> $RESULT
    echo "[시스템 현황]" >> $RESULT
    echo "" >> $RESULT
    VULN=0

    VULN_OWNERS=$(sudo find /var/log/ -type f ! -user root -print -quit)
    VULN_FILES=$(stat -c "%a" /var/log/* | awk '$1 > 644 {print $1}')

    ls -l /var/log/ >> $RESULT

    if [ -n "$VULN_OWNERS" ] || [ -n "$VULN_FILES" ]; then
        VULN=1
    fi

    echo "" >> $RESULT
    echo "" >> $RESULT

    if [ $VULN -eq 1 ]; then
        echo "※ 점검 결과: 취약(Vulnerable)" >> $RESULT
        ((COUNT["VULN"]++))
    else
        echo "※ 점검 결과: 양호(Secure)" >> $RESULT
        ((COUNT["SECURE"]++))
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> $RESULT
}

main(){
    echo "VULNERABILITY CHECK START..."
    for ((j=1; j<=67; j++)); do
        formatted_j=$(printf "%02d" $j)
        func_name="U_$j"
        display_name="U-$formatted_j"

        if $func_name; then
            echo "$display_name Success"
        else
            echo "$display_name Fail"
            echo "-------------------------------------------------------"
            echo "※ 에러 발생: $display_name 실행 중 문제가 발생했습니다."
            echo "점검을 중단합니다."
            echo "-------------------------------------------------------"
            exit 1
        fi
    done
    echo "VULNERABILITY CHECK DONE!"
}
summary(){
    echo "============================== 점검 결과 요약 ==============================" >> $RESULT
    echo "총 점검 항목: 67개" >> $RESULT
    echo "취약: ${COUNT["VULN"]}개" >> $RESULT
    echo "양호: ${COUNT["SECURE"]}개" >> $RESULT
    echo "수동 진단: ${COUNT["SELF"]}개" >> $RESULT
    echo "===========================================================================" >> $RESULT
}

banner
main
summary
