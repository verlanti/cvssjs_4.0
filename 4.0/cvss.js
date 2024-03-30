/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }
                
    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');
    
    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }
    
*/

/* dependencies */

const cvssLookup_global = {
  "000000": 10,
  "000001": 9.9,
  "000010": 9.8,
  "000011": 9.5,
  "000020": 9.5,
  "000021": 9.2,
  "000100": 10,
  "000101": 9.6,
  "000110": 9.3,
  "000111": 8.7,
  "000120": 9.1,
  "000121": 8.1,
  "000200": 9.3,
  "000201": 9,
  "000210": 8.9,
  "000211": 8,
  "000220": 8.1,
  "000221": 6.8,
  "001000": 9.8,
  "001001": 9.5,
  "001010": 9.5,
  "001011": 9.2,
  "001020": 9,
  "001021": 8.4,
  "001100": 9.3,
  "001101": 9.2,
  "001110": 8.9,
  "001111": 8.1,
  "001120": 8.1,
  "001121": 6.5,
  "001200": 8.8,
  "001201": 8,
  "001210": 7.8,
  "001211": 7,
  "001220": 6.9,
  "001221": 4.8,
  "002001": 9.2,
  "002011": 8.2,
  "002021": 7.2,
  "002101": 7.9,
  "002111": 6.9,
  "002121": 5,
  "002201": 6.9,
  "002211": 5.5,
  "002221": 2.7,
  "010000": 9.9,
  "010001": 9.7,
  "010010": 9.5,
  "010011": 9.2,
  "010020": 9.2,
  "010021": 8.5,
  "010100": 9.5,
  "010101": 9.1,
  "010110": 9,
  "010111": 8.3,
  "010120": 8.4,
  "010121": 7.1,
  "010200": 9.2,
  "010201": 8.1,
  "010210": 8.2,
  "010211": 7.1,
  "010220": 7.2,
  "010221": 5.3,
  "011000": 9.5,
  "011001": 9.3,
  "011010": 9.2,
  "011011": 8.5,
  "011020": 8.5,
  "011021": 7.3,
  "011100": 9.2,
  "011101": 8.2,
  "011110": 8,
  "011111": 7.2,
  "011120": 7,
  "011121": 5.9,
  "011200": 8.4,
  "011201": 7,
  "011210": 7.1,
  "011211": 5.2,
  "011220": 5,
  "011221": 3,
  "012001": 8.6,
  "012011": 7.5,
  "012021": 5.2,
  "012101": 7.1,
  "012111": 5.2,
  "012121": 2.9,
  "012201": 6.3,
  "012211": 2.9,
  "012221": 1.7,
  "100000": 9.8,
  "100001": 9.5,
  "100010": 9.4,
  "100011": 8.7,
  "100020": 9.1,
  "100021": 8.1,
  "100100": 9.4,
  "100101": 8.9,
  "100110": 8.6,
  "100111": 7.4,
  "100120": 7.7,
  "100121": 6.4,
  "100200": 8.7,
  "100201": 7.5,
  "100210": 7.4,
  "100211": 6.3,
  "100220": 6.3,
  "100221": 4.9,
  "101000": 9.4,
  "101001": 8.9,
  "101010": 8.8,
  "101011": 7.7,
  "101020": 7.6,
  "101021": 6.7,
  "101100": 8.6,
  "101101": 7.6,
  "101110": 7.4,
  "101111": 5.8,
  "101120": 5.9,
  "101121": 5,
  "101200": 7.2,
  "101201": 5.7,
  "101210": 5.7,
  "101211": 5.2,
  "101220": 5.2,
  "101221": 2.5,
  "102001": 8.3,
  "102011": 7,
  "102021": 5.4,
  "102101": 6.5,
  "102111": 5.8,
  "102121": 2.6,
  "102201": 5.3,
  "102211": 2.1,
  "102221": 1.3,
  "110000": 9.5,
  "110001": 9,
  "110010": 8.8,
  "110011": 7.6,
  "110020": 7.6,
  "110021": 7,
  "110100": 9,
  "110101": 7.7,
  "110110": 7.5,
  "110111": 6.2,
  "110120": 6.1,
  "110121": 5.3,
  "110200": 7.7,
  "110201": 6.6,
  "110210": 6.8,
  "110211": 5.9,
  "110220": 5.2,
  "110221": 3,
  "111000": 8.9,
  "111001": 7.8,
  "111010": 7.6,
  "111011": 6.7,
  "111020": 6.2,
  "111021": 5.8,
  "111100": 7.4,
  "111101": 5.9,
  "111110": 5.7,
  "111111": 5.7,
  "111120": 4.7,
  "111121": 2.3,
  "111200": 6.1,
  "111201": 5.2,
  "111210": 5.7,
  "111211": 2.9,
  "111220": 2.4,
  "111221": 1.6,
  "112001": 7.1,
  "112011": 5.9,
  "112021": 3,
  "112101": 5.8,
  "112111": 2.6,
  "112121": 1.5,
  "112201": 2.3,
  "112211": 1.3,
  "112221": 0.6,
  "200000": 9.3,
  "200001": 8.7,
  "200010": 8.6,
  "200011": 7.2,
  "200020": 7.5,
  "200021": 5.8,
  "200100": 8.6,
  "200101": 7.4,
  "200110": 7.4,
  "200111": 6.1,
  "200120": 5.6,
  "200121": 3.4,
  "200200": 7,
  "200201": 5.4,
  "200210": 5.2,
  "200211": 4,
  "200220": 4,
  "200221": 2.2,
  "201000": 8.5,
  "201001": 7.5,
  "201010": 7.4,
  "201011": 5.5,
  "201020": 6.2,
  "201021": 5.1,
  "201100": 7.2,
  "201101": 5.7,
  "201110": 5.5,
  "201111": 4.1,
  "201120": 4.6,
  "201121": 1.9,
  "201200": 5.3,
  "201201": 3.6,
  "201210": 3.4,
  "201211": 1.9,
  "201220": 1.9,
  "201221": 0.8,
  "202001": 6.4,
  "202011": 5.1,
  "202021": 2,
  "202101": 4.7,
  "202111": 2.1,
  "202121": 1.1,
  "202201": 2.4,
  "202211": 0.9,
  "202221": 0.4,
  "210000": 8.8,
  "210001": 7.5,
  "210010": 7.3,
  "210011": 5.3,
  "210020": 6,
  "210021": 5,
  "210100": 7.3,
  "210101": 5.5,
  "210110": 5.9,
  "210111": 4,
  "210120": 4.1,
  "210121": 2,
  "210200": 5.4,
  "210201": 4.3,
  "210210": 4.5,
  "210211": 2.2,
  "210220": 2,
  "210221": 1.1,
  "211000": 7.5,
  "211001": 5.5,
  "211010": 5.8,
  "211011": 4.5,
  "211020": 4,
  "211021": 2.1,
  "211100": 6.1,
  "211101": 5.1,
  "211110": 4.8,
  "211111": 1.8,
  "211120": 2,
  "211121": 0.9,
  "211200": 4.6,
  "211201": 1.8,
  "211210": 1.7,
  "211211": 0.7,
  "211220": 0.8,
  "211221": 0.2,
  "212001": 5.3,
  "212011": 2.4,
  "212021": 1.4,
  "212101": 2.4,
  "212111": 1.2,
  "212121": 0.5,
  "212201": 1,
  "212211": 0.3,
  "212221": 0.1,
}
const maxSeverity = {
	"eq1": {
		0: 1,
		1: 4,
		2: 5
	},
	"eq2": {
		0: 1,
		1: 2
	},
	"eq3eq6": {
		0: { 0: 7, 1: 6 },
		1: { 0: 8, 1: 8 },
		2: { 1: 10 }
	},
	"eq4": {
		0: 6,
		1: 5,
		2: 4
	},
	"eq5": {
		0: 1,
		1: 1,
		2: 1
	},
}
const maxComposed = {
	// EQ1
	"eq1": {
		0: ["AV:N/PR:N/UI:N/"],
		1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
		2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
	},
	// EQ2
	"eq2": {
		0: ["AC:L/AT:N/"],
		1: ["AC:H/AT:N/", "AC:L/AT:P/"]
	},
	// EQ3+EQ6
	"eq3": {
		0: { "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] },
		1: { "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] },
		2: { "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] },
	},
	// EQ4
	"eq4": {
		0: ["SC:H/SI:S/SA:S/"],
		1: ["SC:H/SI:H/SA:H/"],
		2: ["SC:L/SI:L/SA:L/"]

	},
	// EQ5
	"eq5": {
		0: ["E:A/"],
		1: ["E:P/"],
		2: ["E:U/"],
	},
}

function getEQMaxes(lookup, eq) {
    return maxComposed["eq" + eq][lookup[eq - 1]]
}

function extractValueMetric(metric, str) {
    // indexOf gives first index of the metric, we then need to go over its size
    extracted = str.slice(str.indexOf(metric) + metric.length + 1)
    // remove what follow
    if (extracted.indexOf('/') > 0) {
        metric_val = extracted.substring(0, extracted.indexOf('/'));
    }
    else {
        // case where it is the last metric so no ending /
        metric_val = extracted
    }
    return metric_val
}


function m(cvssSelected, metric) {
    selected = cvssSelected[metric]

    // If E=X it will default to the worst case i.e. E=A
    if (metric == "E" && selected == "X") {
        return "A"
    }
    // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
    if (metric == "CR" && selected == "X") {
        return "H";
    }
    // IR:X is the same as IR:H
    if (metric == "IR" && selected == "X") {
        return "H"
    }
    // AR:X is the same as AR:H
    if (metric == "AR" && selected == "X") {
        return "H"
    }

    // All other environmental metrics just overwrite base score values,
    // so if they’re not defined just use the base score value.
    if (Object.keys(cvssSelected).includes("M" + metric)) {
        modified_selected = cvssSelected["M" + metric]
        if (modified_selected != "X") {
            return modified_selected
        }
    }

    return selected
}


function macroVector(cvssSelected) {
    // EQ1: 0-AV:N and PR:N and UI:N
    //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
    //      2-AV:P or not(AV:N or PR:N or UI:N)

    if (m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N") {
        eq1 = "0"
    }
    else if ((m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")
        && !(m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N")
        && !(m(cvssSelected, "AV") == "P")) {
        eq1 = "1"
    }
    else if (m(cvssSelected, "AV") == "P"
        || !(m(cvssSelected, "AV") == "N" || m(cvssSelected, "PR") == "N" || m(cvssSelected, "UI") == "N")) {
        eq1 = "2"
    }

    // EQ2: 0-(AC:L and AT:N)
    //      1-(not(AC:L and AT:N))

    if (m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N") {
        eq2 = "0"
    }
    else if (!(m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N")) {
        eq2 = "1"
    }

    // EQ3: 0-(VC:H and VI:H)
    //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
    //      2-not (VC:H or VI:H or VA:H)
    if (m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H") {
        eq3 = 0
    }
    else if (!(m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H")
        && (m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
        eq3 = 1
    }
    else if (!(m(cvssSelected, "VC") == "H" || m(cvssSelected, "VI") == "H" || m(cvssSelected, "VA") == "H")) {
        eq3 = 2
    }

    // EQ4: 0-(MSI:S or MSA:S)
    //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
    //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

    if (m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") {
        eq4 = 0
    }
    else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
        (m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H")) {
        eq4 = 1
    }
    else if (!(m(cvssSelected, "MSI") == "S" || m(cvssSelected, "MSA") == "S") &&
        !((m(cvssSelected, "SC") == "H" || m(cvssSelected, "SI") == "H" || m(cvssSelected, "SA") == "H"))) {
        eq4 = 2
    }

    // EQ5: 0-E:A
    //      1-E:P
    //      2-E:U

    if (m(cvssSelected, "E") == "A") {
        eq5 = 0
    }
    else if (m(cvssSelected, "E") == "P") {
        eq5 = 1
    }
    else if (m(cvssSelected, "E") == "U") {
        eq5 = 2
    }

    // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
    //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

    if ((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
        || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
        || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H")) {
        eq6 = 0
    }
    else if (!((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H")
        || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H")
        || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H"))) {
        eq6 = 1
    }

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}


/* -----------------------------------------------*/
var CVSS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        AT: 'Attack Requirements',
        PR: 'Privileges Required',
        UI: 'User Interaction',
        VC: 'Vulnerable System Confidentiality',
        VI: 'Vulnerable System Integrity',
        VA: 'Vulnerable System Availability',
        SC: 'Subsequent System Confidentiality',
        SI: 'Subsequent System Integrity',
        SA: 'Subsequent System Availability'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
                d: "<b>Worst:</b> The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
            },
            A: {
                l: 'Adjacent',
                d: "<b>Worse:</b> The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment."
            },
            L: {
                l: 'Local',
                d: "<b>Bad:</b> The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);</li><li>or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>"
            },
            P: {
                l: 'Physical',
                d: "<b>Bad:</b> The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA)."
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b>Worst:</b> Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
            }
        },
        AT: {
            N: {
                l: 'None',
                d: ""
            },
            P: {
                l: 'Present',
                d: ""
            }
        },
        PR: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack."
            },
            L: {
                l: 'Low',
                d: "<b>Worse</b> The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
            }
        },
        UI: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The vulnerable system can be exploited without interaction from any user."
            },
            P: {
                l: 'Passive',
                d: ""
            },
            A: {
                l: 'Active',
                d: ""
            }
        },
        VC: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of confidentiality within the impacted component."
            }
        },
        VI: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of integrity within the impacted component."
            }
        },
        VA: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to availability within the impacted component."
            }
        },
        SC: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of confidentiality within the impacted component."
            }
        },
        SI: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no loss of integrity within the impacted component."
            }
        },
        SA: {
            H: {
                l: 'High',
                d: "<b>Worst:</b> There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
            },
            L: {
                l: 'Low',
                d: "<b>Bad:</b> Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to availability within the impacted component."
            }
        }
    };
    
    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        AT: 'NP',
        PR: 'NLH',
        UI: 'NPA',
        VC: 'HLN',
        VI: 'HLN',
        VA: 'HLN',
        SC: 'HLN',
        SI: 'HLN',
        SA: 'HLN'
    };

    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
            /* modificare qui */
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_';

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
},
{
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

CVSS.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function () {
    var cvssVersion = "4.0";

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            // metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }

    cvssSelected = val;
    lookup = cvssLookup_global;
    maxSeverityData = maxSeverity;

    /* only base metric */
    cvssSelected['CR'] = "X"
    cvssSelected['IR'] = "X"
    cvssSelected['AR'] = "X"
    cvssSelected['E'] = "X"

    // The following defines the index of each metric's values.
    // It is used when looking for the highest vector part of the
    // combinations produced by the MacroVector respective highest vectors.
    AV_levels = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
    PR_levels = {"N": 0.0, "L": 0.1, "H": 0.2}
    UI_levels = {"N": 0.0, "P": 0.1, "A": 0.2}

    AC_levels = {'L': 0.0, 'H': 0.1}
    AT_levels = {'N': 0.0, 'P': 0.1}

    VC_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
    VI_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}
    VA_levels = {'H': 0.0, 'L': 0.1, 'N': 0.2}

    SC_levels = {'H': 0.1, 'L': 0.2, 'N': 0.3}
    SI_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}
    SA_levels = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}

    CR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}
    IR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}
    AR_levels = {'H': 0.0, 'M': 0.1, 'L': 0.2}

    E_levels = {'U': 0.2, 'P': 0.1, 'A': 0}

    macroVectorResult = macroVector(cvssSelected)

    // Exception for no impact on system (shortcut)
    if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m(cvssSelected, metric) == "N")) {
        return 0.0
    }

    value = lookup[macroVectorResult]
    // 1. For each of the EQs:
    //   a. The maximal scoring difference is determined as the difference
    //      between the current MacroVector and the lower MacroVector.
    //     i. If there is no lower MacroVector the available distance is
    //        set to NaN and then ignored in the further calculations.
    eq1_val = parseInt(macroVectorResult[0])
    eq2_val = parseInt(macroVectorResult[1])
    eq3_val = parseInt(macroVectorResult[2])
    eq4_val = parseInt(macroVectorResult[3])
    eq5_val = parseInt(macroVectorResult[4])
    eq6_val = parseInt(macroVectorResult[5])

    // compute next lower macro, it can also not exist
    eq1_next_lower_macro = "".concat(eq1_val + 1, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val)
    eq2_next_lower_macro = "".concat(eq1_val, eq2_val + 1, eq3_val, eq4_val, eq5_val, eq6_val)

    // eq3 and eq6 are related
    if (eq3 == 1 && eq6 == 1) {
        // 11 --> 21
        eq3eq6_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
    } else if (eq3 == 0 && eq6 == 1) {
        // 01 --> 11
        eq3eq6_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
    } else if (eq3 == 1 && eq6 == 0) {
        // 10 --> 11
        eq3eq6_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
    } else if (eq3 == 0 && eq6 == 0) {
        // 00 --> 01
        // 00 --> 10
        eq3eq6_next_lower_macro_left = "".concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val, eq6_val + 1)
        eq3eq6_next_lower_macro_right = "".concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val)
    } else {
        // 21 --> 32 (do not exist)
        eq3eq6_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val + 1, eq4_val, eq5_val, eq6_val + 1)
    }


    eq4_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val, eq4_val + 1, eq5_val, eq6_val)
    eq5_next_lower_macro = "".concat(eq1_val, eq2_val, eq3_val, eq4_val, eq5_val + 1, eq6_val)


    // get their score, if the next lower macro score do not exist the result is NaN
    score_eq1_next_lower_macro = lookup[eq1_next_lower_macro]
    score_eq2_next_lower_macro = lookup[eq2_next_lower_macro]

    if (eq3 == 0 && eq6 == 0) {
        // multiple path take the one with higher score
        score_eq3eq6_next_lower_macro_left = lookup[eq3eq6_next_lower_macro_left]
        score_eq3eq6_next_lower_macro_right = lookup[eq3eq6_next_lower_macro_right]

        if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) {
            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
        } else {
            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
        }
    } else {
        score_eq3eq6_next_lower_macro = lookup[eq3eq6_next_lower_macro]
    }


    score_eq4_next_lower_macro = lookup[eq4_next_lower_macro]
    score_eq5_next_lower_macro = lookup[eq5_next_lower_macro]

    //   b. The severity distance of the to-be scored vector from a
    //      highest severity vector in the same MacroVector is determined.
    eq1_maxes = getEQMaxes(macroVectorResult, 1)
    eq2_maxes = getEQMaxes(macroVectorResult, 2)
    eq3_eq6_maxes = getEQMaxes(macroVectorResult, 3)[macroVectorResult[5]]
    eq4_maxes = getEQMaxes(macroVectorResult, 4)
    eq5_maxes = getEQMaxes(macroVectorResult, 5)

    // compose them
    max_vectors = []
    for (eq1_max of eq1_maxes) {
        for (eq2_max of eq2_maxes) {
            for (eq3_eq6_max of eq3_eq6_maxes) {
                for (eq4_max of eq4_maxes) {
                    for (eq5max of eq5_maxes) {
                        max_vectors.push(eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5max)
                    }
                }
            }
        }
    }

    // Find the max vector to use i.e. one in the combination of all the highests
    // that is greater or equal (severity distance) than the to-be scored vector.
    for (let i = 0; i < max_vectors.length; i++) {
        max_vector = max_vectors[i]
        severity_distance_AV = AV_levels[m(cvssSelected, "AV")] - AV_levels[extractValueMetric("AV", max_vector)]
        severity_distance_PR = PR_levels[m(cvssSelected, "PR")] - PR_levels[extractValueMetric("PR", max_vector)]
        severity_distance_UI = UI_levels[m(cvssSelected, "UI")] - UI_levels[extractValueMetric("UI", max_vector)]

        severity_distance_AC = AC_levels[m(cvssSelected, "AC")] - AC_levels[extractValueMetric("AC", max_vector)]
        severity_distance_AT = AT_levels[m(cvssSelected, "AT")] - AT_levels[extractValueMetric("AT", max_vector)]

        severity_distance_VC = VC_levels[m(cvssSelected, "VC")] - VC_levels[extractValueMetric("VC", max_vector)]
        severity_distance_VI = VI_levels[m(cvssSelected, "VI")] - VI_levels[extractValueMetric("VI", max_vector)]
        severity_distance_VA = VA_levels[m(cvssSelected, "VA")] - VA_levels[extractValueMetric("VA", max_vector)]

        severity_distance_SC = SC_levels[m(cvssSelected, "SC")] - SC_levels[extractValueMetric("SC", max_vector)]
        severity_distance_SI = SI_levels[m(cvssSelected, "SI")] - SI_levels[extractValueMetric("SI", max_vector)]
        severity_distance_SA = SA_levels[m(cvssSelected, "SA")] - SA_levels[extractValueMetric("SA", max_vector)]

        severity_distance_CR = CR_levels[m(cvssSelected, "CR")] - CR_levels[extractValueMetric("CR", max_vector)]
        severity_distance_IR = IR_levels[m(cvssSelected, "IR")] - IR_levels[extractValueMetric("IR", max_vector)]
        severity_distance_AR = AR_levels[m(cvssSelected, "AR")] - AR_levels[extractValueMetric("AR", max_vector)]


        // if any is less than zero this is not the right max
        if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) {
            continue
        }
        // if multiple maxes exist to reach it it is enough the first one
        break
    }

    current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
    current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
    current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR
    current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA
    current_severity_distance_eq5 = 0

    step = 0.1

    // if the next lower macro score do not exist the result is Nan
    // Rename to maximal scoring difference (aka MSD)
    available_distance_eq1 = value - score_eq1_next_lower_macro
    available_distance_eq2 = value - score_eq2_next_lower_macro
    available_distance_eq3eq6 = value - score_eq3eq6_next_lower_macro
    available_distance_eq4 = value - score_eq4_next_lower_macro
    available_distance_eq5 = value - score_eq5_next_lower_macro

    percent_to_next_eq1_severity = 0
    percent_to_next_eq2_severity = 0
    percent_to_next_eq3eq6_severity = 0
    percent_to_next_eq4_severity = 0
    percent_to_next_eq5_severity = 0

    // some of them do not exist, we will find them by retrieving the score. If score null then do not exist
    n_existing_lower = 0

    normalized_severity_eq1 = 0
    normalized_severity_eq2 = 0
    normalized_severity_eq3eq6 = 0
    normalized_severity_eq4 = 0
    normalized_severity_eq5 = 0

    // multiply by step because distance is pure
    maxSeverity_eq1 = maxSeverityData["eq1"][eq1_val] * step
    maxSeverity_eq2 = maxSeverityData["eq2"][eq2_val] * step
    maxSeverity_eq3eq6 = maxSeverityData["eq3eq6"][eq3_val][eq6_val] * step
    maxSeverity_eq4 = maxSeverityData["eq4"][eq4_val] * step

    //   c. The proportion of the distance is determined by dividing
    //      the severity distance of the to-be-scored vector by the depth
    //      of the MacroVector.
    //   d. The maximal scoring difference is multiplied by the proportion of
    //      distance.
    if (!isNaN(available_distance_eq1)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq1_severity = (current_severity_distance_eq1) / maxSeverity_eq1
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
    }

    if (!isNaN(available_distance_eq2)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq2_severity = (current_severity_distance_eq2) / maxSeverity_eq2
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
    }

    if (!isNaN(available_distance_eq3eq6)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq3eq6_severity = (current_severity_distance_eq3eq6) / maxSeverity_eq3eq6
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
    }

    if (!isNaN(available_distance_eq4)) {
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq4_severity = (current_severity_distance_eq4) / maxSeverity_eq4
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
    }

    if (!isNaN(available_distance_eq5)) {
        // for eq5 is always 0 the percentage
        n_existing_lower = n_existing_lower + 1
        percent_to_next_eq5_severity = 0
        normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
    }

    // 2. The mean of the above computed proportional distances is computed.
    if (n_existing_lower == 0) {
        mean_distance = 0
    } else { // sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
        mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower
    }

    // 3. The score of the vector is the score of the MacroVector
    //    (i.e. the score of the highest severity vector) minus the mean
    //    distance so computed. This score is rounded to one decimal place.
    value -= mean_distance;
    if (value < 0) {
        value = 0.0
    }
    if (value > 10) {
        value = 10.0
    }

    return Math.round(value * 10) / 10

};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/AT:.\/PR:.\/UI:.\/VC:.\/VI:.\/VA:.\/SC:.\/SI:.\/SA:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.prototype.set = function(vec) {
    var newVec = 'CVSS:4.0/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }

    this.update(newVec);
};

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};
