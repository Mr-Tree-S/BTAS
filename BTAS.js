// ==UserScript==
// @name         BTAS
// @namespace    https://github.com/Mr-Tree-S/BTAS
// @homepageURL  https://github.com/Mr-Tree-S/BTAS
// @version      2.3.2
// @description  Blue Team Assistance Script
// @author       Barry Y Yang; Jack SA Chen; Xingyu X Zhou
// @license      Apache-2.0
// @updateURL    https://greasyfork.org/scripts/463908-btas/code/BTAS.user.js
// @downloadURL  https://greasyfork.org/scripts/463908-btas/code/BTAS.user.js
// @match        https://caas.pwchk.com/*
// @icon         https://www.google.com/s2/favicons?domain=pwchk.com
// @require      https://code.jquery.com/jquery-3.6.4.min.js
// @require      https://cdn.jsdelivr.net/npm/clipboard@2.0.11/dist/clipboard.min.js
// @require      https://unpkg.com/@popperjs/core@2/dist/umd/popper.min.js
// @require      https://unpkg.com/tippy.js@6/dist/tippy-bundle.umd.js
// @require      https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js
// @grant        GM_registerMenuCommand
// @grant        GM_unregisterMenuCommand
// @grant        GM_xmlhttpRequest
// @grant        GM_openInTab
// @grant        GM_getValue
// @grant        GM_setValue
// @connect      raw.githubusercontent.com
// @connect      myqcloud.com
// @connect      172.18.4.120
// @run-at       document-idle
// @grant        GM_addStyle
// ==/UserScript==

var $ = window.jQuery;

/**
 * This function creates and displays a flag using AJS.flag function
 * @param {string} type - The type of flag, can be one of the following: "success", "info", "warning", "error"
 * @param {string} title - The title of the flag
 * @param {string} body - The body of the flag
 * @param {string} close - The close of flag, can be one of the following: "auto", "manual", "never"
 */
function showFlag(type, title, body, close) {
    AJS.flag({
        type: type,
        title: DOMPurify.sanitize(title),
        body: DOMPurify.sanitize(body),
        close: close
    });
}

/**
 * This function shows alert message in dialog and create a copy button
 * @param {string} body - Alert Message String
 */
function showDialog(body) {
    // avoid editor treat double backslash as breakline and avoid xss attack
    body = DOMPurify.sanitize(body.replace(/\\\\/g, '\\'));

    // Create custom dialog style
    const customDialogContent = AJS.$(`<section
            id="custom-dialog"
            class="aui-dialog2 aui-dialog2-large aui-layer"
            role="dialog"
            tabindex="-1"
            data-aui-modal="true"
            data-aui-remove-on-hide="true"
            aria-labelledby="dialog-show-button--heading"
            aria-describedby="dialog-show-button--description"
            hidden
        >
            <header class="aui-dialog2-header">
                <h2 class="aui-dialog2-header-main" id="dialog-show-button--heading">Description</h2>
            </header>
            <div class="aui-dialog2-content" id="dialog-show-button--description">
                <p style="word-wrap: break-word; white-space: pre-line">${body}</p>
            </div>
            <footer class="aui-dialog2-footer">
                <div class="aui-dialog2-footer-actions">
                    <button id="dialog-copy-button" class="aui-button aui-button-primary">Copy</button>
                    <button id="dialog-close-button" class="aui-button aui-button-link">Close</button>
                </div>
            </footer>
        </section>`);

    // Show the dialog
    AJS.dialog2(customDialogContent).show();

    // Close the dialog
    AJS.$('#dialog-close-button').on('click', function (e) {
        e.preventDefault();
        AJS.dialog2(customDialogContent).hide();
        //tippy.destroy();
    });

    // Init tippy instance
    tippy('#dialog-copy-button', {
        content: 'Copy Success',
        placement: 'bottom',
        trigger: 'click'
    });

    // Copy description text
    AJS.$('#dialog-copy-button').on('click', function () {
        const textToCopy = customDialogContent.find('p').text().trim();

        // Create Clipboard instance
        const clipboard = new ClipboardJS('#dialog-copy-button', {
            text: function () {
                return textToCopy;
            }
        });

        // Copy success
        clipboard.on('success', function (e) {
            clipboard.destroy();
            e.clearSelection();
        });
    });
}

/**
 * This function registers a Tampermonkey search menu command
 * @param {Array} searchEngines - Search engines array containing the Jira, VT, AbuseIPDB
 */
function registerSearchMenu() {
    console.log('#### Code registerSearchMenu run ####');
    const LogSourceDomain = $('#customfield_10223-val').text().trim() || '*';
    const Host = function () {
        let search = {
            'Source IP(s) and Hostname(s)': $('#customfield_10206-val').text().trim(),
            'Destination IP(s) and Hostname(s)': $('#customfield_10208-val').text().trim()
        };
        if (search['Source IP(s) and Hostname(s)']) {
            return `AND 'Source IP(s) and Hostname(s)' ~ '${search['Source IP(s) and Hostname(s)']}'`;
        } else if (search['Destination IP(s) and Hostname(s)']) {
            return `AND 'Destination IP(s) and Hostname(s)' ~ '${search['Destination IP(s) and Hostname(s)']}'`;
        } else {
            return '';
        }
    };

    const searchEngines = [
        {
            name: 'Jira',
            url:
                'https://caas.pwchk.com/issues/?jql=text%20~%20%22%s%22%20AND%20' +
                '%22Log%20Source%20Domain%22%20~%20%22%D%22%20' +
                `${Host()}` +
                '%20ORDER%20BY%20created%20DESC'
        },
        { name: 'VT', url: 'https://www.virustotal.com/gui/search/%s' },
        { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/check/%s' },
        {
            name: 'Base64 Decode',
            url: `https://icyberchef.com/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=%b`
        }
    ];
    searchEngines.forEach((engine) => {
        GM_registerMenuCommand(engine.name, () => {
            const selectedText = window.getSelection().toString();
            const searchURL = engine.url
                .replace('%s', selectedText)
                .replace('%D', LogSourceDomain)
                .replace('%b', btoa(selectedText));
            if (selectedText.length === 0) {
                showFlag('error', 'No text selected', 'Please select some text and try again', 'auto');
            } else {
                window.open(searchURL, '_blank');
            }
        });
    });
}

/**
 * This function registers custom add/remove quick reply menus in Tampermonkey
 * Add custom reply: input custom reply and store in local
 * Remove quick reply: remove all local storage custom replies
 */
function registerCustomQuickReplyMenu() {
    GM_registerMenuCommand('Add Custom Quick Reply', () => {
        const userInput_name = prompt('Enter saved quick reply name (the name should be unique)').toString();
        const userInput_reply = prompt('Enter a custom quick reply (<br> is used for line break)').toString();
        if (userInput_name !== null && userInput_reply !== null) {
            const key = `customReply_${userInput_name}`;
            // local save
            localStorage.setItem(key, userInput_reply);
        }
    });

    GM_registerMenuCommand('Remove Custom Quick Reply', () => {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('customReply_')) {
                localStorage.removeItem(key);
            }
        }
        showFlag('success', 'Cleared All Custom Replies', '', 'auto');
    });
}

/**
 * This function create a Quick Reply button in editor
 */
function QuickReply() {
    const replyButton = `<button class="aui-button aui-dropdown2-trigger" aria-controls="is-radio-checked">Quick Reply</button>
    <aui-dropdown-menu id="is-radio-checked">
    <aui-section id="reply" label="reply">
        <aui-item-radio interactive>Close ticket</aui-item-radio>
        <aui-item-radio interactive>Monitor ticket</aui-item-radio>
        <aui-item-radio interactive>Waiting ticket</aui-item-radio>
        <aui-item-radio interactive>Waiting Full Scan</aui-item-radio>
        <aui-item-radio interactive>Ask for Whitelist</aui-item-radio>
        <aui-item-radio interactive>Whitelist Done</aui-item-radio>
        <aui-item-radio interactive>Haeco high severity</aui-item-radio>
        <aui-item-radio interactive>Haeco medium severity</aui-item-radio>
        <aui-item-radio interactive>Haeco low severity</aui-item-radio>
        <aui-item-radio interactive>Leaked Credentials</aui-item-radio>
        <aui-item-radio interactive>Compromised Accounts</aui-item-radio>
    </aui-section>
    </aui-dropdown-menu>`;
    const commentBar = $($('.aui-toolbar2-primary')[1]);
    commentBar.append(replyButton);

    const commentBarSection = document.querySelector('aui-section#reply');
    const replyComment = {
        'Close ticket': 'Dear Customer,<br>Thanks for your reply, we will close this ticket.<br>Best Regards.',
        'Monitor ticket': 'Dear Customer,<br>Thanks for your reply, we will keep monitor.<br>Best Regards.',
        'Waiting ticket': 'Dear Customer,<br>Thanks, we look forward to hearing from you.',
        'Waiting Full Scan':
            'Dear Customer,<br>Full scan have been triggered , if suspicious files detected new MDE alert/ticket will be created.',
        'Ask for Whitelist': 'Dear Customer,<br>Can we add the ticket to white list?<br>Best Regards.',
        'Whitelist Done':
            'Dear Customer,<br>We have informed the relevant parties to add this ticket to the white list and will close this ticket<br>Best Regards.',
        'Haeco high severity':
            '<h2><strong><span style="color: red;" data-mce-style="color: red;"><samp>[The ticket is escalated to High Severity]</samp></span></strong></h2><br>',
        'Haeco medium severity':
            '<h2><span style="color: rgb(255, 171, 0);" data-mce-style="color: #ffab00;"><strong><samp>[The ticket is escalated to Medium Severity]</samp></strong></span></h2><br>',
        'Haeco low severity':
            '<h2><span style="color: rgb(76, 154, 255);" data-mce-style="color: #4c9aff;"><strong><samp>[The ticket is de-escalated to Low Severity]</samp></strong></span></h2><br>',
        'Leaked Credentials':
            '<p>Dear Client,</p><p>Our Cyber Threat Intelligence investigated the incident and found &lt;Number&gt; leaked credentials related to your organization exposed in dark web. The credentials are listed below:</p><table width="962" class="mce-item-table"><tbody><tr><td width="137"><div><p><strong>EMAIL</strong></p></div></td><td width="137"><div><p><strong>PASSWORD TYPE</strong></p></div></td><td width="137"><div><p><strong>PASSWORD</strong></p></div></td><td width="137"><div><p><strong>SOURCE</strong></p></div></td><td width="137"><div><p><strong>PRICE</strong></p></div></td><td width="137"><div><p><strong>POSTED DATE</strong></p></div></td><td width="137"><div><p><strong>SERVICE</strong></p></div></td></tr><tr><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td></tr></tbody></table><p>[Source Detail from Kela]</p><p>&lt;SOURCE Details/Description&gt;</p><p>[Service if disclose need check]</p><p>As per our open-source investigation through passive means, we observe that:</p><p>&lt; SERVICE&gt; appear to be &lt;SERVICE USAGE&gt;</p><p>[Recommendation]</p><p>We recommend confirming that the service coverage is to customers only, or whether it also includes staff and/or third-party, and evaluate if accounts with administrative privileges require a password change. &nbsp;We also recommend to heighten monitoring of customer login to indicate anomalies in location or timing, and review password policies and evaluate if there is a need to strengthen (e.g., mandate password rotation regularly). A further recommendation is to reach out to these account holders if the accounts are still active, and request that they change their passwords.</p><p>Please do not hesitate to reach out to us if you have any queries. Thank you.</p><p>Best Regards,<br>Cyber Threat Intelligence Team</p>',
        'Compromised Accounts':
            '<p>Dear Client,</p><p>Our Cyber Threat Intelligence investigated the incident and found&nbsp;&lt;Number&gt; compromised accounts related to your organisation exposed in dark web. The credentials are listed below:</p><table width="962" class="mce-item-table"><tbody><tr><td width="137"><div><p><strong>EMAIL</strong></p></div></td><td width="137"><div><p><strong>PASSWORD TYPE</strong></p></div></td><td width="137"><div><p><strong>PASSWORD</strong></p></div></td><td width="137"><div><p><strong>SOURCE</strong></p></div></td><td width="137"><div><p><strong>PRICE</strong></p></div></td><td width="137"><div><p><strong>POSTED DATE</strong></p></div></td><td width="137"><div><p><strong>SERVICE</strong></p></div></td></tr><tr><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td><td width="137"><br data-mce-bogus="1"></td></tr></tbody></table><p>[Source Detail from Kela]</p><p>&lt;SOURCE Details/Description&gt;</p><p>[Service if disclose need check]</p><p>As per our open-source investigation through passive means, we observe that:</p><p>&lt; SERVICE&gt; appear to be &lt;SERVICE USAGE&gt;&nbsp;</p><p>[Recommendation]</p><p>We recommend confirming that the service coverage is to customers only, or whether it also includes staff and/or third-party, and evaluate if accounts with administrative privileges require a password change. &nbsp;We also recommend to heighten monitoring of customer login to indicate anomalies in location or timing, and review password policies and evaluate if there is a need to strengthen (e.g., mandate password rotation regularly). A further recommendation is to reach out to these account holders if the accounts are still active, and request that they change their passwords.</p><p>Please do not hesitate to reach out to us if you have any queries. Thank you.</p><p>Best Regards,<br>Cyber Threat Intelligence Team</p>'
    };

    // Check local storage at initialization time
    function getAllCustomReply() {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('customReply_')) {
                const storedReply = localStorage.getItem(key).toString();
                const storeReplyName = key.split('_')[1].toString();
                replyComment[storeReplyName] = storedReply;
                $('#reply').append(`<aui-item-radio interactive>${storeReplyName}</aui-item-radio>`);
            }
        }
    }
    getAllCustomReply();

    try {
        if (commentBarSection !== null) {
            commentBarSection.addEventListener('change', function (e) {
                if (e.target.hasAttribute('checked')) {
                    tinymce.activeEditor.setContent('');
                    let replyValue = replyComment[e.target.textContent];
                    tinymce.activeEditor.execCommand('mceInsertContent', false, replyValue);
                }
            });
        }
    } catch (error) {
        console.error(error);
    }
}

/**
 * This function registers two Tampermonkey exception menu command
 * Add Exception: adds the currently selected text to an exception list stored in local storage
 * Clear Exception: clears the exception list from local storage
 */
let exceptionKey = localStorage.getItem('exceptionKey')?.split(',') || [];
let notifyKey = [...exceptionKey];

/**jsonView */
function jsonToTree(data) {
    let flag = false;
    let html = '<ul class="code-java" style="list-style-type: none;margin-top: 0px;padding-left: 20px;">';
    if (Array.isArray(data)) {
        let temp = '[';
        data.forEach((element) => {
            temp += jsonToTree(element);
        });
        html += temp + '],';
    } else if (data != null && typeof data === 'object' && Object.keys(data).length !== 0) {
        flag = true;
        for (let key in data) {
            if (data.hasOwnProperty(key)) {
                html += '<li class="code-quote">"' + key + '": ';
                if (Array.isArray(data[key])) {
                    let temp = '[';
                    data[key].forEach((element) => {
                        temp += jsonToTree(element);
                    });
                    html += temp + '],';
                } else if (typeof data[key] === 'object') {
                    try {
                        if (Object.keys(data[key]).length == 0) {
                            html += '{},';
                        } else {
                            const str = jsonToTree(data[key]);
                            html += str;
                        }
                    } catch (TypeError) {
                        html += '"",';
                    }
                } else {
                    html += '"' + data[key].toString() + '",';
                }
                html += '</li>';
            }
        }
    } else {
        html += '"' + data.toString() + '",';
    }
    if (flag === true) {
        html = '{' + html + '},';
    }
    html += '</ul>';
    return html;
}

function registerExceptionMenu() {
    console.log('#### Code registerExceptionMenu run ####');
    GM_registerMenuCommand('Add Exception', () => {
        const selection = window.getSelection().toString().trim();
        if (!selection) {
            showFlag('error', 'No Issue Key selected', '', 'auto');
            return;
        }
        exceptionKey.push(selection);
        localStorage.setItem('exceptionKey', exceptionKey.toString());
        showFlag('success', '', `Added <strong>${selection}</strong> successfully`, 'auto');
    });

    GM_registerMenuCommand('Clear Exception', () => {
        localStorage.setItem('exceptionKey', '');
        exceptionKey = notifyKey = [];
        showFlag('success', 'Cleared All Issue Key', '', 'auto');
    });

    GM_registerMenuCommand('JsonViewer', () => {
        var isJson = function (str) {
            try {
                JSON.parse(str);
            } catch (e) {
                showFlag('error', 'Please select json format data', '', 'auto');
                return false;
            }
            return true;
        };
        let selection = window.getSelection().toString().trim();
        if (!selection) {
            showFlag('error', 'No Issue Key selected', '', 'auto');
            return;
        } else if (isJson(selection)) {
            var jsonData = jsonToTree(JSON.parse(selection));
            /**  var jsonView = document.createElement('pre');
            jsonView.textContent = JSON.stringify(jsonData,null,2);
            **/
            showDialog(jsonData, 'Json Format');
        }
    });
}

/**
 * This function creates audio and checkbox controls and adds them to the Jira share button's parent node
 * @returns {Object} Object containing references to the audio control and audio checkbox, keep checkbox, prompt checkbox
 */
// ## In the future, the alert sound will be migrated to another server, and more fun music will be added.
function createNotifyControls() {
    console.log('#### Code createNotifyControls run ####');
    const operationsBar = $('div.saved-search-operations.operations');
    const audioControl = $('<span></span>');

    function createAudioControl(parentNode) {
        const currentDate = new Date();
        const audioURL =
            currentDate.getHours() >= 9 && currentDate.getHours() < 21
                ? 'https://gitee.com/aspirepig/aspirepig/raw/master/12221.wav'
                : 'https://gitee.com/aspirepig/aspirepig/raw/master/alerts.wav';
        audioControl.html(`<audio src="${audioURL}" type="audio/mpeg" controls></audio>`);
        parentNode.prepend(audioControl);
    }

    function createCheckbox(parentNode, localStorageKey, checkStatus) {
        const checkbox = $('<span></span>');
        const value = localStorage.getItem(localStorageKey);
        checkbox.html(
            `<input type="checkbox" name="${localStorageKey}" ${
                value == 'true' ? 'checked' : checkStatus ? 'checked' : ''
            }>${localStorageKey}`
        );
        checkbox.find('input').on('click', () => {
            localStorage.setItem(localStorageKey, checkbox.find('input').prop('checked'));
        });
        parentNode.prepend(checkbox);
        return checkbox;
    }
    createAudioControl(operationsBar);
    const audioCheckbox = createCheckbox(operationsBar, 'audioNotify', false);
    const keepCheckbox = createCheckbox(operationsBar, 'keepAudio', false);
    const promptCheckbox = createCheckbox(operationsBar, 'prompt', true);

    return { audioControl, audioCheckbox, keepCheckbox, promptCheckbox };
}

/**
 * Check for updates in the issues list and play a sound if new issues are found
 * @param {Object} NotifyControls - Object containing the audio control, audio checkbox, keep checkbox, prompt checkbox
 */
function checkupdate(NotifyControls) {
    console.log('#### Code checkupdate run ####');
    const { audioControl, audioCheckbox, keepCheckbox, promptCheckbox } = NotifyControls;
    const table = $('tbody');
    if (!table.length) return;

    let Tickets = '';
    table.find('tr').each(function () {
        const summary = $(this).find('.summary p').text().trim();
        const issuekey = $(this).find('.issuekey a.issue-link').attr('data-issue-key');
        if (!notifyKey.includes(issuekey)) {
            notifyKey.push(issuekey);
            Tickets += `${summary}==${issuekey}\n`;
        }
    });
    if (Tickets || keepCheckbox.find('input').prop('checked')) {
        if (audioCheckbox.find('input').prop('checked')) {
            audioControl.find('audio').get(0).currentTime = 0;
            audioControl.find('audio').get(0).play();
        }
    }

    $('.aui-banner').remove();
    let overdueTickets = '';
    table.find('tr').each(function () {
        const issuekey = $(this).find('.issuekey a.issue-link').attr('data-issue-key');
        const datetime = new Date($(this).find('.updated time').attr('datetime'));
        const currentTime = new Date();
        const diffMs = currentTime - datetime;
        const diffMinutes = Math.floor(diffMs / 60000);
        if (diffMinutes > 30 && diffMinutes < 120) {
            overdueTickets += `<a href="https://caas.pwchk.com/browse/${issuekey}" target="_blank">${issuekey}</a>, `;
        }
    });
    if (overdueTickets && promptCheckbox.find('input').prop('checked')) {
        GM_addStyle(`
        .aui-banner.aui-banner-warning {
            background-color: #ffab00 !important;
            color: black !important;
        }
    `);
        AJS.banner({
            body: `Ticket: ${overdueTickets}<br>30 minutes have passed since the ticket's status changed, please handle it as soon as possible`,
            type: 'warning'
        });
    }
}

/**
 * This function checks for specific keywords within a string
 * Advises the user to double-check and contact L2 or TL if suspicious.
 */
function checkKeywords() {
    console.log('#### Code checkKeywords run ####');

    function parseCSV(csv) {
        const lines = csv.trim().split('\r\n'); // 将CSV拆分成行
        const header = lines[0].split(','); // 解析标题行
        const data = [];

        for (let i = 1; i < lines.length; i++) {
            const values = lines[i].split(',');
            const entry = {};

            for (let j = 0; j < header.length; j++) {
                entry[header[j]] = values[j];
            }
            data.push(entry);
        }
        return data;
    }

    function fetchKeywordsList() {
        GM_xmlhttpRequest({
            method: 'GET',
            url: 'https://aspirepig-1251964320.cos.ap-shanghai.myqcloud.com/keywords.csv',
            onload: function (response) {
                if (response.status === 200) {
                    const keywords = parseCSV(response.responseText);
                    const rawLog = $('#customfield_10219-val').text().trim().toLowerCase();

                    for (const keyword of keywords) {
                        if (rawLog.includes(keyword['Keyword'].toLowerCase())) {
                            AJS.banner({
                                body: `\"${keyword['Keyword']}\" was found in the ticket, it is maybe used for "${keyword['Remark']}", please double-check and contact L2 or TL if suspicious.`
                            });
                        }
                    }
                } else {
                    console.error('Error fetching Keywords List:', response.status);
                }
            },
            onerror: function (error) {
                console.error('Error fetching Keywords List:', error);
            }
        });
    }

    fetchKeywordsList();
}

/**
 * This function is used for checking Orgnazation field
 */
function checkOrg() {
    const projectType = $('#project-name-val').text().trim();

    if (projectType == 'MSS') {
        // 监视页面动态元素的变化，出现edit-issue-submit时绑定事件
        const observer = new MutationObserver(() => {
            if (document.getElementById('edit-issue-submit')) {
                // 先解绑事件，再绑定，避免重复绑定
                $('#edit-issue-submit').off('click');
                $('#edit-issue-submit').click((e) => {
                    e.preventDefault(); // 阻止表单提交
                    const organization =
                        DOMPurify.sanitize(
                            $('#customfield_10002-multi-select > div.representation > ul > li').text().trim()
                        ) || '';
                    const LogSourceDomain = DOMPurify.sanitize($('#customfield_10223').val().trim()) || '';
                    const orgDict = {
                        'nanfung': ['Nanfung'],
                        'je-pilot': ['JE-pilot', 'JE-Past'],
                        'welab': ['WELAB'],
                        'jsshk': ['JSSHK'],
                        'hashkey': ['HASHKEY'],
                        'kerrypropshk': ['KerryPropsHK'],
                        'newworld': ['NWS', 'NWD-OnPrem', 'NWD-Network', 'NWD-Cloud', 'K11-OnPrem', 'NWD'],
                        'k11-cn': ['K11-CN', 'K11-OnPrem'],
                        'spac-haeco-hk': ['SPAC-Haeco-HK'],
                        'k11-hk': ['K11-CN', 'NWD-Cloud', 'K11-Network', 'K11-OnPrem', 'K11-Cloud', 'K11', 'K11-Luxba'],
                        'spac-haesl-hk': ['SPAC-Haesl-HK'],
                        'spac-motors': ['SPAC-Motors'],
                        'toysrus': ['TOYSRUS'],
                        'swireproperties': ['Swireprop-unclassified', 'SPL_CHINA', 'SPL_HK', 'SHG_CHINA', 'SHG_HK'],
                        'ckah': ['CKAH'],
                        'spac-scc-hk-aws': ['SPAC-SCC-HK-AWS'],
                        'lsh-kr-hsmcl': ['LSH-KR-HSMCL'],
                        'mizuho-sc': ['MIZUHO-SC'],
                        'aeon': ['AEON', 'AEON CLOUD'],
                        'huatai': ['HTSC'],
                        'ctfj': ['CTFJ'],
                        'esf-is': ['ESF-IS'],
                        'esf-dc': [
                            'ESF-IS',
                            'ESF-SC',
                            'ESF-DC',
                            'ESF-KGV',
                            'ESF-WIS',
                            'ESF-DISCOVERYCOLLEGE',
                            'ESF-HQ',
                            'ESF-SJS',
                            'ESF-QBS',
                            'ESF-BHS',
                            'ESF-JCSRS',
                            'ESF-BS'
                        ],
                        'nws': ['NWS'],
                        'spac-haeco-amrhcs': ['SPAC-Haeco-AMRHCS'],
                        'esf-sc': ['ESF-SC'],
                        'esf-kgv': ['ESF-KGV'],
                        'hkbn': ['HKBN'],
                        'esf-sis': ['ESF-SIS'],
                        'ctfe': ['CTFE'],
                        'spac-resources-hk': ['SPAC-Resources-HK'],
                        'hkexpress': ['HKEXPRESS'],
                        'spac-sugar-hk': ['SPAC-Sugar-HK'],
                        'maxims-hk': ['MAXIMS-HK', 'MAXIMS-HKCloud', 'MAXIMS-HKServer'],
                        'hktvmall': ['HKTVMALL'],
                        'spac-scc-hk-onprem': ['SPAC-SCC-HK-ONPrem'],
                        'esf-wis': ['ESF-WIS'],
                        'esf-discoverycollege': ['ESF-DISCOVERYCOLLEGE'],
                        'toppanmerrill': ['TOPPAN'],
                        'lsh-tw': ['LSH-TW'],
                        'lsh-vn': ['LSH-VN'],
                        'sino': ['SINO'],
                        'esf-kjs': ['ESF-KJS'],
                        'esf-hq': ['ESF-DISCOVERYCOLLEGE', 'ESF-HQ', 'ESF-RC', 'ESF-BHS'],
                        'tvb': ['TVB'],
                        'kef': ['KEF'],
                        'esf-ks': ['ESF-KS'],
                        'citysuper': ['C!S'],
                        'hkgta': ['HKGTA'],
                        'lsh-hk': ['LSH-HK-Corp', 'LSH-HK-Corp-SAP', 'LSH-HK-Auto-SAP', 'LSH-HK-Auto'],
                        'spac-scc-tw-onprem': ['SPAC-SCC-TW-ONPrem'],
                        'esf-rc': ['ESF-RC'],
                        'hkuniversity': ['HKU-CPOS'],
                        'bossini': ['BOS'],
                        'lsh-kr-smc': ['LSH-KR-SMC'],
                        'NewWorld': ['K11-CN', 'NWD-Network', 'K11-Network', 'K11'],
                        'esf-sjs': ['ESF-SJS'],
                        'glshk': ['GLSHK'],
                        'esf-cwbs': ['ESF-CWBS'],
                        'jetco': ['Jetco'],
                        'esf-qbs': ['ESF-QBS'],
                        'goldpeak': ['GOLDPEAK'],
                        'mdb': ['MDB'],
                        'wynn': ['WYNN'],
                        'esf-abs': ['ESF-ABS'],
                        'NWD-Network': ['NWD-Network'],
                        'cityu': ['CityU'],
                        'esf-ps': ['ESF-PS'],
                        'esf-gs': ['ESF-GS'],
                        'spac-haeco-dfw': ['SPAC-Haeco-DFW'],
                        'SPAC-YoungDomain': ['Swireprop-unclassified', 'SPAC-YoungDomain'],
                        'esf-bhs': ['ESF-BHS'],
                        'kadensa': ['Kadensa'],
                        'melco': ['MELCO'],
                        'esf-hs': ['ESF-HS'],
                        'MDB': ['MDB'],
                        'esf-bs': ['ESF-BS'],
                        'esf-jcsrs': ['ESF-JCSRS'],
                        'esf-tyk': ['ESF-TYK'],
                        'esf-wksk': ['ESF-WKSK'],
                        'JSSHK': ['JSSHK'],
                        'SPAC-Haeco-HK': ['SPAC-Haeco-HK'],
                        'HKTVMALL': ['HKTVMALL'],
                        'qvp': ['QVP'],
                        'SPAC-Motors': ['SPAC-Motors'],
                        'esf-tck': ['ESF-TCK'],
                        'fung': ['FUNG HK'],
                        'hthk': ['HTHK'],
                        'K11-Network': ['K11-Network'],
                        'pwcsoc': ['SOC'],
                        'SPAC-HAECO-HK': ['SPAC-Haeco-HK'],
                        'CTFJ': ['CTFJ'],
                        'ESF-WIS': ['ESF-WIS', 'ESF-HQ'],
                        'Goldpeak': ['GOLDPEAK'],
                        'JE-pilot': ['JE-pilot'],
                        'KerryPropsHK': ['KerryPropsHK'],
                        'nwd': ['NWD'],
                        'nwd-cloud': ['NWD-Cloud'],
                        'safeguards': ['SAFEGUARDS'],
                        'SPAC-SCC-HK-ONPrem': ['SPAC-SCC-HK-ONPrem']
                    };

                    try {
                        if (organization == '') {
                            let result = confirm('请填写 Organization 字段，若不升级请点击取消忽略该提示');
                            if (!result) {
                                $('#edit-issue-submit').off('click'); // 点击取消则不再弹出提示
                            }
                        } else if (orgDict[organization] == undefined) {
                            // 当前客户不在配置列表中，直接提交
                            $('#edit-issue-submit').off('click');
                            document.getElementById('edit-issue-submit').click();
                        } else if (!orgDict[LogSourceDomain].includes(organization)) {
                            let alertinfo = `Organization:${organization}\nLog Source Doamin:${LogSourceDomain}\n所选 Organization 不符，请升级到 ${LogSourceDomain} 后再提交\n若确认所选 Organization 无误，请点击取消忽略该提示`;
                            let result = confirm(DOMPurify.sanitize(alertinfo));
                            if (!result) {
                                $('#edit-issue-submit').off('click'); // 点击取消则不再弹出提示
                            }
                        } else {
                            // 如果验证通过，则解绑事件再模拟点击提交
                            $('#edit-issue-submit').off('click');
                            document.getElementById('edit-issue-submit').click();
                        }
                    } catch (error) {
                        if (
                            error.name === 'TypeError' &&
                            error.message == "Cannot read properties of undefined (reading 'includes')"
                        ) {
                            $('#edit-issue-submit').off('click'); // 对于LogSourceDomain为空或者LogSourceDomain不在列表的工单跳过验证
                            document.getElementById('edit-issue-submit').click();
                        } else {
                            throw error;
                        }
                    }
                });
            }
        });

        // 绑定目标节点并启动监视者
        observer.observe(document.body, { childList: true });
    }
}

/**
 * This function is used for checking ATT&CK field
 */
function checkATTCK() {
    const status = $('#opsbar-transitions_more > span').text().trim();
    const attck = $('#rowForcustomfield_10220 > div > strong > label').text();
    if (status == 'Waiting for customer' && attck == '') {
        AJS.banner({ body: `The ATT&CK field is not filled in` });
    }
}

/**
 * This function is used for popping up MSS ticket considerations when clicked "Edit" and "Resolved" button or page loading.
 * Ticket Considerations file is store in cloud server
 * @param {Object} pageData - Gets the specified fields from the jira page
 */
function ticketNotify(pageData) {
    console.log('#### Code ticketNotify run ####');

    function fetchOrgNotifydict() {
        // 从本地存储获取缓存的文件内容和上次更新时间
        const cachedContent = GM_getValue('cachedFileContent', null);

        GM_xmlhttpRequest({
            method: 'GET',
            url: 'https://172.18.4.120/api/7vVKD9hF/notifys/',
            headers: {
                'api-key': 'Tnznjha3yhJgA7YG'
            },
            timeout: 2000, // 超过2秒未获取到文件则使用缓存文件
            onload: function (response) {
                if (response.status === 200) {
                    const data = JSON.parse(response.responseText);

                    // 本地无缓存，第一次获取文件保存到本地
                    if (cachedContent == null) {
                        // 更新本地存储中的文件内容和更新时间
                        GM_setValue('cachedFileContent', data);

                        checkNotify(data.items, pageData);
                        generateNotify();
                    }

                    // 如果本地存储中有缓存，并且文件内容有变化
                    if (cachedContent !== null && JSON.stringify(cachedContent) !== JSON.stringify(data)) {
                        // 更新本地存储中的文件内容
                        GM_setValue('cachedFileContent', data);

                        // 使用最新文件
                        checkNotify(data.items, pageData);
                    }

                    // 本地存在缓存，且内容相同则使用缓存文件
                    if (cachedContent !== null && JSON.stringify(cachedContent) == JSON.stringify(data)) {
                        checkNotify(cachedContent.items, pageData);
                        generateNotify();
                    }
                } else {
                    console.error('Error fetching orgNotifydict:', response.status);
                }
            },
            ontimeout: function () {
                // 未连接 Darklab VPN 时使用缓存文件
                if (cachedContent !== null) {
                    checkNotify(cachedContent.items, pageData);
                    generateNotify();
                } else {
                    showFlag('Error', '文件获取失败', '未连接到 Darklab VPN，请连接后刷新页面', 'auto');
                }
            },
            onerror: function (error) {
                console.error('Error:', error);
            }
        });
    }
    fetchOrgNotifydict();

    function checkNotify(Notifydict, pageData) {
        // get button path
        const buttonMap = {
            Edit: '#edit-issue',
            Resolve: '#action_id_761',
            None: ''
        };

        function checkProperties(properties, pageData, ticketname) {
            const condition = (property) => {
                const propertyArray = property.propertiesVal.split(',');
                for (const val of propertyArray) {
                    try {
                        if (pageData[property.propertiesKey].includes(val)) {
                            return true;
                        }
                    } catch (error) {
                        if (
                            error.name === 'TypeError' &&
                            error.message == "Cannot read properties of undefined (reading 'includes')"
                        ) {
                            console.warn(`${ticketname} 提醒未加条件，请检查配置`);
                        }
                    }
                }
            };

            return properties.reduce((acc, property) => {
                return acc && condition(property);
            }, true);
        }

        for (const notify of Notifydict) {
            const { ticketname, starttime, endtime, message, properties, button, status } = notify;
            const isInTimeRange =
                (!starttime || new Date() >= new Date(starttime)) && (!endtime || new Date() <= new Date(endtime));
            const clickButton = buttonMap[button];

            if (status == 'Disable' || !isInTimeRange) {
                continue;
            }

            if (checkProperties(properties, pageData, ticketname)) {
                if (clickButton == '') {
                    showFlag('warning', `${ticketname} ticket`, `${message.replace(/\r?\n/g, '<br>')}`, 'manual');
                } else {
                    $(clickButton).on('click', () => {
                        showFlag('warning', `${ticketname} ticket`, `${message.replace(/\r?\n/g, '<br>')}`, 'manual');
                    });
                }
            }
        }
    }

    // add a element into toolbar
    function generateNotify() {
        const toolbar = $('.aui-toolbar2-primary');
        const element = $('<div id="generateTicketNotify"></div>');
        toolbar.append(element);
    }
}
/**
 * Creates a new button and adds it to the DOM.
 * @param {string} id - The ID attribute for the new button element.
 * @param {string} text - The text content to display on the new button.
 * @param {string} onClick - The function to call when the button is clicked.
 */
function addButton(id, text, onClick) {
    console.log(`#### Add Button: ${text}  ####`);
    const toolbar = $('.aui-toolbar2-primary');
    toolbar.append(`
        <div class="aui-buttons pluggable-ops">
        <a id="${id}" onclick="${onClick}" class="aui-button toolbar-trigger">
            <span class="trigger-label">${text}</span>
        </a>
        </div>
    `);
    $('#' + id).click(onClick);
}

/**
 * Creates three buttons on a JIRA issue page to handle Cortex XDR alerts
 * The buttons allow users to generate a description of the alerts, open the alert card page and timeline page
 */
function cortexAlertHandler(...kwargs) {
    console.log('#### Code cortexAlertHandler run ####');
    const { LogSourceDomain } = kwargs[0];
    const rawLog = $('#field-customfield_10232 > div.twixi-wrap.verbose > div > div > div > pre').text();
    /**
     * Extracts the log information and organization name from the current JIRA issue page
     * @param {Object} orgDict - A dictionary that maps organization name to navigator name
     * @returns {Object} An object that contains the organization's name, organization's navigator URL, raw log information
     */
    const orgDict = {
        'bossini': 'https://bossini.xdr.sg.paloaltonetworks.com/',
        'hkuniversity': 'https://cpos.xdr.sg.paloaltonetworks.com/',
        'citysuper': 'https://citysuper.xdr.sg.paloaltonetworks.com/',
        'esf-dc': 'https://esf.xdr.us.paloaltonetworks.com/',
        'glshk': 'https://glshk.xdr.us.paloaltonetworks.com/',
        'kerrylogistics': 'https://kerrylogistics.xdr.us.paloaltonetworks.com/',
        'k11-hk': 'https://k11.xdr.sg.paloaltonetworks.com/',
        'newworld': 'https://nwcs.xdr.sg.paloaltonetworks.com/',
        'nws': 'https://nws.xdr.sg.paloaltonetworks.com/',
        'toppanmerrill': 'https://tpm-apac.xdr.us.paloaltonetworks.com/',
        'welab': 'https://welabbank.xdr.sg.paloaltonetworks.com/',
        'goldpeak': 'https://gpbi-poc.xdr.sg.paloaltonetworks.com/',
        'hkbn': 'https://elite.xdr.sg.paloaltonetworks.com/',
        'cityu': 'https://cityu.xdr.us.paloaltonetworks.com/',
        'hthk': 'https://hthk.xdr.sg.paloaltonetworks.com/'
    };
    const orgNavigator = orgDict[LogSourceDomain];

    /**
     * Parse the relevant information from the raw log data
     * @param {Array} rawLog - An array of JSON strings representing the raw log data
     * @returns {Array} An array of objects containing the alert relevant information
     */
    function parseLog(rawLog) {
        let alertInfo = [];
        try {
            const { cortex_xdr } = JSON.parse(rawLog).data;
            const { source, alert_id, name, description } = cortex_xdr;
            const isPANNGFW = source === 'PAN NGFW';
            const alert = { source, alert_id, name, description };
            if (isPANNGFW) {
                const {
                    action_local_ip,
                    action_local_port,
                    action_remote_ip,
                    action_remote_port,
                    action_pretty,
                    alert_link
                } = cortex_xdr;
                alertInfo.push({
                    ...alert,
                    action_local_ip,
                    action_local_port,
                    action_remote_ip,
                    action_remote_port,
                    action_pretty,
                    alert_link
                });
            } else {
                const {
                    action_local_ip,
                    action_file_macro_sha256,
                    action_file_name,
                    action_file_path,
                    action_file_sha256,
                    action_process_image_name,
                    action_process_image_sha256,
                    action_process_image_command_line,
                    actor_process_image_name,
                    actor_process_image_path,
                    actor_process_image_sha256,
                    actor_process_command_line,
                    causality_actor_process_image_name,
                    causality_actor_process_command_line,
                    causality_actor_process_image_path,
                    causality_actor_process_image_sha256,
                    os_actor_process_image_name,
                    os_actor_process_image_path,
                    os_actor_process_command_line,
                    os_actor_process_image_sha256,
                    action_pretty,
                    host_name,
                    host_ip,
                    user_name,
                    alert_link
                } = cortex_xdr;
                const action_list = {
                    action_file_name,
                    action_file_path,
                    action_file_sha256,
                    action_process_image_name,
                    action_process_image_sha256,
                    action_process_image_command_line
                };
                const actor_list = {
                    actor_process_image_name,
                    actor_process_image_path,
                    actor_process_image_sha256,
                    actor_process_command_line
                };
                const causality_actor_list = {
                    causality_actor_process_image_name,
                    causality_actor_process_command_line,
                    causality_actor_process_image_path,
                    causality_actor_process_image_sha256
                };
                const os_actor_list = {
                    os_actor_process_image_name,
                    os_actor_process_image_path,
                    os_actor_process_command_line,
                    os_actor_process_image_sha256
                };

                function countValidProperties(obj) {
                    const validPropsCount = Object.keys(obj).reduce((count, key) => {
                        if (obj[key] !== undefined) {
                            count++;
                        }
                        return count;
                    }, 0);
                    return validPropsCount;
                }

                const actionPropsCount = countValidProperties(action_list) ? countValidProperties(action_list) + 1 : 0;
                const actorPropsCount = countValidProperties(actor_list);
                const causalityPropsCount = countValidProperties(causality_actor_list);
                const osPropsCount = countValidProperties(os_actor_list);
                const maxCount = Math.max(actionPropsCount, actorPropsCount, causalityPropsCount, osPropsCount);

                const action_cmd_length = action_process_image_command_line
                    ? action_process_image_command_line.length
                    : 0;
                const actor_cmd_length = actor_process_command_line ? actor_process_command_line.length : 0;
                const causality_cmd_length = causality_actor_process_command_line
                    ? causality_actor_process_command_line.length
                    : 0;
                const os_cmd_length = os_actor_process_command_line ? os_actor_process_command_line.length : 0;
                const lengths = [action_cmd_length, actor_cmd_length, causality_cmd_length, os_cmd_length];
                const maxLength = Math.max(...lengths);

                let filename;
                let filepath;
                let sha256;
                let cmd;

                if (action_cmd_length === maxLength && actionPropsCount === maxCount) {
                    filename = action_file_name || action_process_image_name;
                    filepath = action_file_path;
                    cmd = action_process_image_command_line;
                    sha256 = action_file_sha256 || action_process_image_sha256;
                } else if (actor_cmd_length === maxLength && actorPropsCount === maxCount) {
                    filename = actor_process_image_name;
                    filepath = actor_process_image_path;
                    cmd = actor_process_command_line;
                    sha256 = actor_process_image_sha256;
                } else if (causality_cmd_length === maxLength && causalityPropsCount === maxCount) {
                    filename = causality_actor_process_image_name;
                    filepath = causality_actor_process_image_path;
                    cmd = causality_actor_process_command_line;
                    sha256 = causality_actor_process_image_sha256;
                } else if (os_actor_process_image_name && osPropsCount === maxCount) {
                    filename = os_actor_process_image_name;
                    filepath = os_actor_process_image_path;
                    cmd = os_actor_process_command_line;
                    sha256 = os_actor_process_image_sha256;
                }

                alertInfo.push({
                    ...alert,
                    host_name,
                    host_ip,
                    alert_link,
                    user_name,
                    filename,
                    filepath,
                    cmd,
                    sha256,
                    action_pretty,
                    action_local_ip,
                    action_file_macro_sha256
                });
            }
        } catch (error) {
            console.error(`Error: ${error.message}`);
        }

        return alertInfo;
    }
    const alertInfo = parseLog(rawLog);

    /**
     * Define three functions for handling alert information:
     * generateDescription creates a description for each alert, and displays the combined description in an alert box
     * openCard opens a new window to display the alert card page for each alert
     * openTimeline opens a new window to display the timeline page for each alert
     */
    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const {
                source,
                name,
                action_local_ip,
                action_local_port,
                action_remote_ip,
                action_remote_port,
                action_pretty,
                host_name,
                host_ip,
                user_name,
                filename,
                filepath,
                cmd,
                sha256,
                description,
                action_file_macro_sha256,
                alert_link
            } = info;
            if (source === 'PAN NGFW') {
                const desc = `Observed ${name}\nSrcip: ${action_local_ip}   Srcport: ${action_local_port}\nDstip: ${action_remote_ip}   Dstport: ${action_remote_port}\nAction: ${action_pretty}\n${
                    LogSourceDomain === 'cityu' ? 'Cortex Portal: ' + alert_link + '\n' : ''
                }\n\nPlease help to verify if this activity is legitimate.\n`;
                alertDescriptions.push(desc);
            } else {
                const desc = `Observed ${description || name}\nHost: ${host_name}   IP: ${host_ip}\n${
                    action_local_ip ? 'action_local_ip: ' + action_local_ip + '\n' : ''
                }username: ${user_name}\ncmd: ${cmd}\nfilename: ${filename}\nfilepath: ${filepath}\naction: ${action_pretty}\n${
                    action_file_macro_sha256 ? 'macro file hash: ' + action_file_macro_sha256 + '\n' : ''
                }https://www.virustotal.com/gui/file/${action_file_macro_sha256 || sha256}\n${
                    LogSourceDomain === 'cityu' ? 'Cortex Portal: ' + alert_link + '\n' : ''
                }\n\nPlease help to verify if this activity is legitimate.\n`;
                alertDescriptions.push(desc);
            }
            const toolbarSha256 = $('.aui-toolbar2-inner');
            if (sha256 && !toolbarSha256.clone().children().remove().end().text().trim().includes(sha256)) {
                toolbarSha256.append(`${sha256} `);
            }
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    function openCard() {
        for (const info of alertInfo) {
            const { source, alert_id } = info;
            if (orgNavigator) {
                let cardURL;
                switch (source) {
                    case 'XDR Analytics':
                        cardURL = `${orgNavigator}card/analytics2/${alert_id}`;
                        break;
                    case 'Correlation':
                        cardURL = `${orgNavigator}alerts/${alert_id}`;
                        break;
                    default:
                        cardURL = `${orgNavigator}card/alert/${alert_id}`;
                        break;
                }
                window.open(cardURL, '_blank');
            } else {
                showFlag('error', '', `There is no <strong>${LogSourceDomain}</strong> Navigator on Cortex`, 'auto');
            }
        }
    }
    function openTimeline() {
        for (const info of alertInfo) {
            const { source, alert_id } = info;
            if (orgNavigator) {
                let timelineURL;
                switch (source) {
                    case 'Correlation':
                        showFlag(
                            'error',
                            '',
                            `Source of the Alert is <strong>${source}</strong>, There is no Timeline on Cortex`,
                            'auto'
                        );
                        break;
                    default:
                        timelineURL = `${orgNavigator}forensic-timeline/alert_id/${alert_id}`;
                        break;
                }
                timelineURL && window.open(timelineURL, '_blank');
            } else {
                showFlag('error', '', `There is no <strong>${LogSourceDomain}</strong> Navigator on Cortex`, 'auto');
            }
        }
    }
    addButton('generateDescription', 'Description', generateDescription);
    addButton('openCard', 'Card', openCard);
    addButton('openTimeline', 'Timeline', openTimeline);
}

/**
 * Create Description and Open MDE button
 * @param  {...any} kwargs - Include LogSourceDomain, Labels, LogSource, TicketAutoEscalate, Status, RawLog, Summary fields
 */
function MDEAlertHandler(...kwargs) {
    console.log('#### Code MDEAlertHandler run ####');
    const { rawLog } = kwargs[0];
    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const formatJson = log.substring(log.indexOf('{')).trim();
                const logObj = JSON.parse(formatJson.replace(/\\\(n/g, '\\n('));
                const { mde } = logObj;
                const { title, id, computerDnsName, relatedUser, evidence } = mde;
                const alert = { title, id, computerDnsName };
                const userName = relatedUser ? relatedUser.userName : 'N/A';
                let extrainfo = '';
                if (evidence) {
                    const tmp = [];
                    for (const evidenceItem of evidence) {
                        let description = '';
                        if (evidenceItem.entityType === 'File') {
                            description = `filename: ${evidenceItem.fileName}\nfilePath: ${evidenceItem.filePath}\nsha1: ${evidenceItem.sha1}`;
                            tmp.push(description);
                        }
                        if (evidenceItem.entityType === 'Process') {
                            description = `cmd: ${evidenceItem.processCommandLine}\naccount: ${evidenceItem.accountName}\nsha1: ${evidenceItem.sha1}`;
                            tmp.push(description);
                        }
                        if (evidenceItem.entityType === 'Url') {
                            description += `Url: ${evidenceItem.url}`;
                            tmp.push(description);
                        }
                        if (evidenceItem.entityType === 'Ip') {
                            description += `IP: ${evidenceItem.ipAddress}`;
                            tmp.push(description);
                        }
                        //tmp.push(description);
                    }
                    const uniqueDescriptions = Array.from(new Set(tmp));
                    extrainfo = uniqueDescriptions.join('\n');
                }
                acc.push({ ...alert, userName, extrainfo });
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }
    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { title, computerDnsName, userName, extrainfo } = info;
            const desc = `Observed ${title}\nHost: ${computerDnsName}\nusername: ${userName}\n${extrainfo}\n\nPlease help to verify if it is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }
    function openMDE() {
        let MDEURL = '';
        for (const info of alertInfo) {
            const { id } = info;
            if (id) {
                MDEURL += `https://security.microsoft.com/alerts/${id}\n`;
            }
        }
        showFlag('info', 'MDE URL:', `${MDEURL}`, 'manual');
    }
    addButton('generateDescription', 'Description', generateDescription);
    addButton('openMDE', 'MDE', openMDE);
}

function HTSCAlertHandler(...kwargs) {
    console.log('#### Code HTSCAlertHandler run ####');
    const { rawLog } = kwargs[0];
    function decodeHtml(encodedString) {
        const tmpElement = document.createElement('span');
        tmpElement.innerHTML = encodedString;
        return tmpElement.innerText;
    }

    const parseLog = (rawLog) => {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const formatJson = log.substring(log.indexOf('{')).trim();
                // const logObj = JSON.parse(formatJson);
                const logObj = JSON.parse(formatJson.replace(/\\\(n/g, '\\n('));
                const eventEvidence = decodeHtml(logObj.event_evidence).split('End time')[0];
                const alert = {
                    attackType: logObj.tag,
                    hostRisk: logObj.hostRisk,
                    srcIP: logObj.src_ip,
                    eventEvidence,
                    hostName: logObj.hostName,
                    dstIP: logObj.dst_ip
                };
                acc.push(alert);
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
            return acc;
        }, []);
        return alertInfo;
    };
    const alertInfo = parseLog(rawLog);
    // console.info(`alertInfo: ${alertInfo}`);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { attackType, hostRisk, srcIP, hostName, dstIP, eventEvidence } = info;
            const desc = `Observed ${attackType} Attack\nhostRisk: ${hostRisk}\nSrc_IP: ${srcIP}\nhostname: ${hostName}\nDst_IP: ${dstIP}\nevent_evidence: ${eventEvidence}\n\nPlease help to verify if this activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }
    addButton('generateDescription', 'Description', generateDescription);
}

function VMCEFAlertHandler(...kwargs) {
    const { rawLog } = kwargs[0];

    function parseCefLog(rawLog) {
        function cefToJson(cefLog) {
            let json = {};
            let fields = cefLog.split(' ');

            for (let i = 0; i < fields.length; i++) {
                let field = fields[i].split('=');
                let key = field[0];
                let value = field.slice(1).join('=');

                if (value) {
                    if (key === 'filePath' || key === 'msg' || key === 'start' || key === 'rt') {
                        let nextFieldIndex = i + 1;
                        while (nextFieldIndex < fields.length && !fields[nextFieldIndex].includes('=')) {
                            value += ' ' + fields[nextFieldIndex];
                            nextFieldIndex++;
                        }
                    }
                    json[key] = value;
                }
            }
            return json;
        }

        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                // Determine whether the log is empty
                if (Object.keys(log).length !== 0) {
                    // Split CEF log
                    let cef_log = log.split('|');
                    // Parsing CEF Header
                    const cef_log_header = cef_log.slice(1, 7);
                    // Parsing CEF Extends
                    const cef_log_extends = cefToJson(cef_log[7]);

                    acc.push({
                        Summary: cef_log_header[4],
                        // for some like "server error" tickets
                        HostName: cef_log_extends.dhost ? cef_log_extends.dhost : cef_log_extends.dvchost,
                        HostIp: cef_log_extends.dst,
                        UserName: cef_log_extends.duser,
                        FileName: cef_log_extends.fname,
                        FilePath: cef_log_extends.filePath,
                        Sha256: cef_log_extends.fileHash,
                        Msg: cef_log_extends.msg
                    });
                }
                return acc;
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
        }, []);
        return alertInfo;
    }
    const alertInfo = parseCefLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { Summary } = info;
            let desc = `Observed ${Summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && index != 'Summary' && index != 'CBlink') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function CBAlertHandler(...kwargs) {
    console.log('#### Code CBAlertHandler run ####');
    const { rawLog } = kwargs[0];

    function parseLeefLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            const cb_log = {};
            try {
                const log_obj = log.split('\t');
                log_obj.forEach((log_item) => {
                    try {
                        const [key, value] = log_item.split('=');
                        cb_log[key] = value;
                    } catch (error) {
                        console.error(`Error: ${error.message}`);
                    }
                });
                if (log.trim() !== '') {
                    acc.push({
                        Summary: cb_log.watchlist_name,
                        HostName: cb_log.computer_name,
                        HostIp: cb_log.interface_ip,
                        UserName: cb_log.username,
                        CmdLine: cb_log.cmdline,
                        CBlink: cb_log.link_process,
                        Filepath: cb_log.path,
                        Sha256: cb_log.process_sha256
                    });
                }
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }

    const alertInfo = parseLeefLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { Summary } = info;
            let desc = `Observed ${Summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && index != 'Summary' && index != 'CBlink') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    function openCB() {
        let CBURL = '';
        for (const info of alertInfo) {
            const { CBlink } = info;
            if (CBlink) {
                CBURL += `${CBlink}\n`;
            }
        }
        showFlag('info', 'CB URL:', `${CBURL}`, 'manual');
    }

    addButton('generateDescription', 'Description', generateDescription);
    addButton('openCB', 'CB', openCB);
}

function WineventAlertHandler(...kwargs) {
    console.log('#### Code WineventAlertHandler run ####');
    let { rawLog, summary } = kwargs[0];
    summary = summary.replace(/[\[(].*?[\])]/g, '');
    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const { win } = JSON.parse(log);
                const { eventdata, system } = win;
                const alertHost = system.computer;
                acc.push({ summary, alertHost, eventdata });
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }
    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed${info.summary}\nHost: ${info.alertHost}\n`;
            for (const key in info.eventdata) {
                if (Object.hasOwnProperty.call(info.eventdata, key)) {
                    const value = info.eventdata[key];
                    if (value !== undefined) {
                        desc += `${key}: ${value}\n`;
                    }
                }
            }
            desc += '\n' + 'Please help to verify if this activity is legitimate.' + '\n';
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function FortigateAlertHandler(...kwargs) {
    let { rawLog, summary } = kwargs[0];
    summary = summary.split(']')[1].trim();
    function ParseFortigateLog(rawLog) {
        const alertInfos = rawLog.reduce((acc, log) => {
            if (log == '') {
                return acc;
            }
            let jsonData = {};
            const regex = /(\w+)=(["'].*?["']|\S+)/g;
            let matchresult;
            while ((matchresult = regex.exec(log)) !== null) {
                let key = matchresult[1];
                let value = matchresult[2];
                if (value.startsWith('"') && value.endsWith('"')) {
                    value = value.slice(1, -1);
                } else if (value.startsWith("'") && value.endsWith("'")) {
                    value = value.slice(1, -1);
                }
                jsonData[key] = value;
            }
            acc.push(jsonData);
            return acc;
        }, []);
        return [...new Set(alertInfos)];
    }

    const alertInfos = ParseFortigateLog(rawLog);

    function ExtractAlertInfo(alertInfos) {
        const extract_alert_infos = alertInfos.reduce((acc, alertInfo) => {
            const {
                srcip,
                srcport,
                srccountry,
                dstip,
                dstport,
                dstcountry,
                hostname,
                url,
                referralurl,
                action,
                devname,
                user,
                cfgattr,
                msg,
                forwardedfor
            } = alertInfo;
            const extract_alert_info = {
                srcip: srcip ? `${srcip}:${srcport}[${srccountry}]` : undefined,
                dstip: dstip ? `${dstip}:${dstport}[${dstcountry}]` : undefined,
                hostname: hostname,
                devname: devname,
                user: user,
                url: url,
                action: action,
                cfgattr: cfgattr,
                msg: msg,
                referralurl: referralurl,
                forwardedfor: forwardedfor || undefined
            };
            acc.push(extract_alert_info);
            return acc;
        }, []);
        return extract_alert_infos;
    }
    const extract_alert_infos = ExtractAlertInfo(alertInfos);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of extract_alert_infos) {
            let desc = `Observed ${summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined) {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function CSAlertHandler(...kwargs) {
    let { rawLog } = kwargs[0];
    function parseCefLog(rawLog) {
        function cefToJson(cefLog) {
            let json = {};
            let fields = cefLog.split(' ');

            for (let i = 0; i < fields.length; i++) {
                let field = fields[i].split('=');
                let key = field[0];
                let value = field.slice(1).join('=');

                if (value) {
                    if (key === 'filePath' || key === 'msg' || key === 'cs5' || key === 'start' || key === 'rt') {
                        let nextFieldIndex = i + 1;
                        while (nextFieldIndex < fields.length && !fields[nextFieldIndex].includes('=')) {
                            value += ' ' + fields[nextFieldIndex];
                            nextFieldIndex++;
                        }
                    }
                    json[key] = value;
                }
            }
            return json;
        }

        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                // Determine whether the log is empty
                if (Object.keys(log).length !== 0) {
                    // Split CEF log
                    let cef_log = log.split('|');
                    // Parsing CEF Header
                    const cef_log_header = cef_log.slice(1, 7);
                    // Parsing CEF Extends
                    const cef_log_extends = cefToJson(cef_log[7]);

                    acc.push({
                        Summary: cef_log_header[4],
                        // for some like "server error" tickets
                        HostName: cef_log_extends.dhost ? cef_log_extends.dhost : cef_log_extends.dvchost,
                        HostIp: cef_log_extends.dst,
                        UserName: cef_log_extends.duser,
                        FileName: cef_log_extends.fname,
                        FilePath: cef_log_extends.filePath,
                        Command: cef_log_extends.cs5,
                        Sha256: cef_log_extends.fileHash,
                        Msg: cef_log_extends.msg,
                        CSLink: cef_log_extends.cs6
                    });
                }
                return acc;
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
        }, []);
        return alertInfo;
    }

    const alertInfo = parseCefLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { Summary } = info;
            let desc = `Observed ${Summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && index != 'Summary' && index != 'CSLink') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }
    function openCS() {
        let CSURL = '';
        for (const info of alertInfo) {
            const { CSLink } = info;
            if (CSLink) {
                CSURL += `${CSLink.replace('hXXps', 'https').replace(/[\[\]]/g, '')}<br><br>`;
            }
        }
        showFlag('info', 'CS URL:', `${CSURL}`, 'manual');
    }
    addButton('generateDescription', 'Description', generateDescription);
    addButton('openCS', 'CS', openCS);
}

function SophosAlertHandler(...kwargs) {
    let { rawLog } = kwargs[0];
    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                log.replace(/[\[(].*?[\])]/g, '');
                const { sophos, logsource } = JSON.parse(log);
                const summary = sophos.name;
                const alertHost = sophos.dhost;
                const alertUser = sophos.suser;
                const alertID = sophos.id;
                const alertIP = sophos?.source_info?.ip || sophos?.data?.source_info?.ip || '';
                const alertExtraInfo = {
                    'Sha256': sophos.appSha256,
                    'Filename': sophos?.data?.fileName ? sophos.data.fileName : undefined,
                    'Processname': sophos?.data?.processName ? sophos.data.processName : undefined,
                    'Process': sophos?.data?.process ? sophos.data.process : undefined,
                    'Clean Up Result': sophos?.core_remedy_items?.items[0]?.result
                };
                acc.push({ summary, alertHost, alertIP, alertUser, alertID, logsource, alertExtraInfo });
            } catch (error) {
                console.log(`Error: ${error.message}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }
    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed ${info.summary}\nHost: ${info.alertHost} IP: ${info.alertIP || 'N/A'}\nUser: ${
                info.alertUser
            }\n`;
            for (const key in info.alertExtraInfo) {
                if (Object.hasOwnProperty.call(info.alertExtraInfo, key)) {
                    const value = info.alertExtraInfo[key];
                    if (value !== undefined) {
                        desc += `${key}: ${value}\n`;
                    }
                }
            }
            desc += '\n' + 'Please help to verify if this activity is legitimate.' + '\n';
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    function openSophos() {
        let searchID = '';
        for (const info of alertInfo) {
            const { alertHost, alertID, logsource } = info;
            if (alertID || alertHost) {
                searchID += `<strong>[${logsource}] ${alertHost}</strong>:<br>${alertID}<br><br>`;
            }
        }
        showFlag('info', 'Host and Alert ID', `${searchID}`, 'manual');
        GM_openInTab('https://cloud.sophos.com/manage/enterprise/alerts-list', {
            active: false, // 设置为 false，以在后台打开，不激活新标签页
            insert: true // 设置为 true，将新标签页插入到当前标签页之后
        });
    }

    addButton('generateDescription', 'Description', generateDescription);
    addButton('openSophos', 'Open Sophos', openSophos);
}

function SpemAlertHandler(...kwargs) {
    const { rawLog, summary } = kwargs[0];

    function parseLog(rawLog) {
        let logObject = {};
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                logArray = log.split(',');
                logArray[10] = 'Action:' + logArray[10];
                for (const index of logArray) {
                    const [key, value] = index.split(/:(.+)/, 2);
                    logObject[key] = value;
                }
                acc.push({
                    'Summary': logObject['Event Description'] !== undefined ? logObject['Event Description'] : summary,
                    'User Name': logObject['User Name'],
                    'Local Host IP': logObject['Local Host IP'],
                    'Local Port': logObject['Local Port'],
                    'Remote Host IP': logObject['Remote Host IP'],
                    'Remote Port': logObject['Remote Port'],
                    'Application': logObject['Application'],
                    'SHA-256': logObject['SHA-256'],
                    'Intrusion URL': logObject['Intrusion URL'],
                    'Action': logObject['Action']
                });
            } catch (error) {
                console.log(`Error: ${error}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }

    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed ${info['Summary']}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && value !== ' ' && index != 'Summary') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function AwsAlertHandler(...kwargs) {
    const { rawLog, summary } = kwargs[0];

    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const { aws } = JSON.parse(log);
                acc.push({
                    SourceIP: aws.sourceIPAddress,
                    User: aws.userIdentity.arn,
                    UserAgent: aws.userAgent,
                    PrincipalId: aws.userIdentity.principalId,
                    Result: aws.errorCode
                });
            } catch (error) {
                console.log(`Error: ${error}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }

    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed ${summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && value !== ' ' && index != 'Summary') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function Defender365AlertHandler(...kwargs) {
    const { rawLog } = kwargs[0];

    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                let jsonLog = JSON.parse(log);
                const alerts = jsonLog['incidents']['alerts'][0];
                let entities = {};
                if (alerts !== undefined) {
                    alerts['entities'].forEach(function (entity) {
                        if (entity['entityType'] == 'User') {
                            entities['user'] = `${entity['domainName']}\\\\${entity['accountName']}`;
                        }

                        if (entity['entityType'] == 'Process') {
                            if (!entities['process']) {
                                entities['process'] = [];
                            }
                            entities['process'].push({
                                filename: entity['fileName'],
                                filePath: entity['filePath'],
                                cmd: entity['processCommandLine'],
                                sha256: entity['sha256']
                            });
                        }

                        if (entity['entityType'] == 'File') {
                            if (!entities['file']) {
                                entities['file'] = [];
                            }
                            entities['file'].push({
                                filename: entity['fileName'],
                                filePath: entity['filePath'],
                                sha256: entity['sha256']
                            });
                        }

                        if (entity['entityType'] == 'Ip') {
                            if (!entities['ip']) {
                                entities['ip'] = [];
                            }
                            entities['ip'].push({
                                ip: entity['ipAddress']
                            });
                        }
                    });
                }
                acc.push({
                    summary: jsonLog['incidents'].incidentName,
                    host: alerts?.devices[0]?.deviceDnsName,
                    user: entities.user,
                    process: entities.process,
                    file: entities.file,
                    ip: entities.ip,
                    alertid: alerts?.alertId,
                    incidenturi: jsonLog['incidents'].incidentUri
                });
            } catch (error) {
                console.log(`Error: ${error}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }
    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed ${info.summary}\n`;
            try {
                for (let key in info) {
                    if (info.hasOwnProperty(key)) {
                        if (Array.isArray(info[key])) {
                            info[key].forEach((item) => {
                                for (let subKey in item) {
                                    if (item.hasOwnProperty(subKey) && item[subKey] !== '') {
                                        desc += `${subKey}: ${item[subKey]}\n`;
                                    }
                                }
                            });
                        } else {
                            if (
                                info[key] !== undefined &&
                                info[key] !== ' ' &&
                                key !== 'summary' &&
                                key !== 'alertid' &&
                                key !== 'incidenturi'
                            ) {
                                desc += `${key}: ${info[key]}\n`;
                            }
                        }
                    }
                }
            } catch (error) {
                console.error(`Error: ${error}`);
            }

            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    function openMDE() {
        let MDEURL = '';
        for (const info of alertInfo) {
            const { alertid, incidenturi } = info;
            if (alertid && !MDEURL.includes(alertid)) {
                MDEURL += `https://security.microsoft.com/alerts/${alertid}<br><br>`;
            }
            if (!alertid && incidenturi) {
                MDEURL += incidenturi.replace('hXXps[:]', 'https:') + '<br><br>';
            }
        }
        showFlag('info', 'MDE URL:', `${MDEURL}`, 'manual');
    }

    addButton('generateDescription', 'Description', generateDescription);
    addButton('openMDE', 'MDE', openMDE);
}

function AzureAlertHandler(...kwargs) {
    const { rawLog } = kwargs[0];

    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const { eventhub, azure } = JSON.parse(log);
                const { ExtendedProperties, Entities } = eventhub;
                let entities = {};
                if (Entities) {
                    Entities.forEach(function (entity) {
                        if (entity.Type === 'host') {
                            entities['host'] = entity['HostName'];
                        }
                        if (entity.Type === 'network-connection') {
                            entities['SourceIP'] = entity['SourceAddress']['Address'];
                        }
                    });
                }
                acc.push({
                    summary: azure['ThreatDescription'] || eventhub['AlertDisplayName'],
                    Protocol: azure['Protocol'],
                    SourceIP: azure['SourceIp'],
                    SourcePort: azure['SourcePort'],
                    DestinationIp: azure['DestinationIp'],
                    DestinationPort: azure['DestinationPort'],
                    URL: azure['Url'],
                    Action: azure['Action'],
                    alerturi: eventhub['AlertUri'],
                    ExtendedProperties: JSON.stringify(ExtendedProperties, null, 4),
                    ...entities
                });
            } catch (error) {
                console.log(`Error: ${error}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }

    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            let desc = `Observed ${info.summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && value !== '' && index !== 'summary' && index !== 'alerturi') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    function openAzure() {
        let AzureURL = '';
        for (const info of alertInfo) {
            const { alerturi } = info;
            if (alerturi) {
                AzureURL += `${alerturi.replace('hXXps', 'https').replace(/\[|\]/g, '')}<br><br>`;
            }
        }
        showFlag('info', 'Azure URL:', `${AzureURL}`, 'manual');
    }

    addButton('generateDescription', 'Description', generateDescription);
    addButton('openAzure', 'Azure', openAzure);
}

function paloaltoAlertHandler(...kwargs) {
    const { rawLog, summary } = kwargs[0];

    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                let logArray = log.split(',');
                let logType = logArray[3];
                if (logType == 'TRAFFIC') {
                    acc.push({
                        'Summary': summary.split(']')[1],
                        'Source IP': logArray[7],
                        'Destination IP': logArray[8],
                        'Destination Port': logArray[25],
                        'Destination Location': logArray[42] != 0 ? logArray[42] : logArray[39]
                    });
                }
                if (logType == 'THREAT') {
                    acc.push({
                        'Source IP': logArray[7],
                        'Destination IP': logArray[8],
                        'Destination Port': logArray[25],
                        'Destination Location': logArray[42] != 0 ? logArray[42] : logArray[39],
                        'IoC': logArray[31],
                        'Summary': summary.split(']')[1]
                    });
                }
            } catch (error) {
                console.error(`Error:${error}`);
            }
            return acc;
        }, []);
        return alertInfo;
    }

    const alertInfo = parseLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            if (info.Summary == undefined) {
                continue;
            }
            let desc = `Observed ${info.Summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && value !== '' && index !== 'Summary') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

function ImpervaincCEFAlertHandler(...kwargs) {
    const { rawLog } = kwargs[0];

    function parseCefLog(rawLog) {
        function cefToJson(cefLog) {
            let json = {};
            let fields = cefLog.split(' ');

            for (let i = 0; i < fields.length; i++) {
                let field = fields[i].split('=');
                let key = field[0];
                let value = field.slice(1).join('=');

                if (value) {
                    if (key === 'filePath' || key === 'msg' || key === 'start' || key === 'rt' || key === 'cs1') {
                        let nextFieldIndex = i + 1;
                        while (nextFieldIndex < fields.length && !fields[nextFieldIndex].includes('=')) {
                            value += ' ' + fields[nextFieldIndex];
                            nextFieldIndex++;
                        }
                    }
                    json[key] = value;
                }
            }
            return json;
        }

        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                // Determine whether the log is empty
                if (Object.keys(log).length !== 0) {
                    // Split CEF log
                    let cef_log = log.split('|');
                    // Parsing CEF Header
                    const cef_log_header = cef_log.slice(1, 7);
                    // Parsing CEF Extends
                    const cef_log_extends = cefToJson(cef_log[7]);

                    acc.push({
                        summary: cef_log_extends.cs1,
                        // for some like "server error" tickets
                        username: cef_log_extends.duser,
                        srcIP: cef_log_extends.src,
                        dstIP: cef_log_extends.dst,
                        dstPort: cef_log_extends.dpt,
                        protocol: cef_log_extends.proto
                    });
                }
                return acc;
            } catch (error) {
                console.error(`Error: ${error.message}`);
            }
        }, []);
        return alertInfo;
    }
    const alertInfo = parseCefLog(rawLog);

    function generateDescription() {
        const alertDescriptions = [];
        for (const info of alertInfo) {
            const { summary } = info;
            let desc = `Observed ${summary}\n`;
            Object.entries(info).forEach(([index, value]) => {
                if (value !== undefined && index != 'summary' && index != 'CBlink') {
                    desc += `${index}: ${value}\n`;
                }
            });
            desc += `\nPlease verify if the activity is legitimate.\n`;
            alertDescriptions.push(desc);
        }
        const alertMsg = [...new Set(alertDescriptions)].join('\n');
        showDialog(alertMsg);
    }

    addButton('generateDescription', 'Description', generateDescription);
}

(function () {
    'use strict';

    registerSearchMenu();
    registerExceptionMenu();
    registerCustomQuickReplyMenu();
    checkOrg();

    // Filter page: audio control registration and regular issues table update
    if (
        (window.location.href.includes('filter=15200') || window.location.href.includes('filter=26405')) &&
        !window.location.href.includes('MSS')
    ) {
        console.log('#### Code includes filter run ####');
        const NotifyControls = createNotifyControls();

        setInterval(() => {
            $('.aui-button.aui-button-primary.search-button').click();
            setTimeout(checkupdate(NotifyControls), 5000);
            if (window.location.href.includes('filter=15200')) {
                notifyKey = [];
                window.location.href = 'https://caas.pwchk.com/issues/?filter=15200';
            }
            if (window.location.href.includes('filter=26405')) {
                notifyKey = [];
                window.location.href = 'https://caas.pwchk.com/issues/?filter=26405';
            }
        }, 180000);
    }

    // Issue page: Alert Handler
    setInterval(() => {
        const LogSourceDomain = $('#customfield_10223-val').text().trim();
        const rawLog = $('#field-customfield_10219 > div:first-child > div:nth-child(2)').text().trim().split('\n');
        const summary = $('#summary-val').text().trim();
        if ($('#issue-content').length && !$('#generateDescription').length) {
            console.log('#### Code Issue page: Alert Handler ####');
            const handlers = {
                'cortex-xdr-json': cortexAlertHandler,
                'mde-api-json': MDEAlertHandler,
                'sangfor-ccom-json': HTSCAlertHandler,
                'carbonblack': CBAlertHandler,
                'carbonblack_cef': VMCEFAlertHandler,
                'windows_eventchannel': WineventAlertHandler,
                'fortigate-firewall-v5': FortigateAlertHandler,
                'crowdstrike_cef': CSAlertHandler,
                'sophos': SophosAlertHandler,
                'sepm-security': SpemAlertHandler,
                'sepm-traffic': SpemAlertHandler,
                'vmwarecarbonblack_cef': VMCEFAlertHandler,
                'aws-cloudtrail': AwsAlertHandler,
                'm365-defender-json': Defender365AlertHandler,
                'azureeventhub': AzureAlertHandler,
                'paloalto-firewall': paloaltoAlertHandler,
                'impervainc_cef': ImpervaincCEFAlertHandler
            };
            const DecoderName = $('#customfield_10807-val').text().trim().toLowerCase();
            const handler = handlers[DecoderName];
            if (handler) {
                handler({ LogSourceDomain: LogSourceDomain, rawLog: rawLog, summary: summary });
            }
        }
    }, 1000);

    // Issue page: check Keywords and ATT&CK and Org
    setTimeout(() => {
        if ($('#issue-content').length && !$('.aui-banner-error').length) {
            console.log('#### Code Issue page: check Keywords ####');
            checkKeywords();
            checkATTCK();
        }
    }, 4500);

    // Issue page: Edit Notify
    setTimeout(() => {
        const LogSourceDomain = $('#customfield_10223-val').text().trim();
        const Labels = $('.labels-wrap .labels li a span').text();
        const LogSource = $('#customfield_10204-val').text().trim();
        const DecoderName = $('#customfield_10807-val').text().trim().toLowerCase();
        const TicketAutoEscalate = $('#customfield_12202-val').text().trim();
        const Status = $('#status-val > span').text().trim();
        const RawLog =
            $('#field-customfield_10219 > div:first-child > div:nth-child(2)').text().trim() ||
            $('#field-customfield_10232 > div.twixi-wrap.verbose > div > div > div > pre').text();
        const Summary = $('#summary-val').text().trim();
        const pageData = {
            LogSourceDomain,
            Labels,
            LogSource,
            DecoderName,
            TicketAutoEscalate,
            Status,
            RawLog,
            Summary
        };
        // If it pops up once, it will not be reminded again
        if ($('#issue-content').length && !$('#generateTicketNotify').length) {
            console.log('#### Code Issue page: Edit Notify ####');
            ticketNotify(pageData);
        }
    }, 1000);

    // Issue page: Quick Reply
    setInterval(() => {
        if (document.querySelector('#reply') == null) {
            QuickReply();
        }
    }, 3000);
})();
