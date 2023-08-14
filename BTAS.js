// ==UserScript==
// @name         BTAS
// @namespace    https://github.com/Ripper-S/BTAS
// @homepageURL  https://github.com/Ripper-S/BTAS
// @version      1.6.6
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
// @grant        GM_registerMenuCommand
// @grant        GM_unregisterMenuCommand
// @grant        GM_xmlhttpRequest
// @connect      raw.githubusercontent.com
// @connect      myqcloud.com
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
        title: title,
        body: body,
        close: close
    });
}

function showDialog(body) {
    // Create custom dialog style
    const customDialogContent = AJS.$(`<section
            id="custom-dialog"
            class="aui-dialog2 aui-dialog2-small aui-layer"
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
        tippy.destroy();
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
    const searchEngines = [
        {
            name: 'Jira',
            url:
                'https://caas.pwchk.com/issues/?jql=text%20~%20%22%s%22%20AND%20' +
                '%22Log%20Source%20Domain%22%20~%20%22%D%22%20' +
                'ORDER%20BY%20created%20DESC'
        },
        // { name: 'Reputation', url: 'https://172.18.2.23/instance/execute/reputation/ip?ip=%s' },
        { name: 'VT', url: 'https://www.virustotal.com/gui/search/%s' },
        { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/check/%s' }
    ];
    searchEngines.forEach((engine) => {
        GM_registerMenuCommand(engine.name, () => {
            const selectedText = window.getSelection().toString();
            const searchURL = engine.url.replace('%s', selectedText).replace('%D', LogSourceDomain);
            if (selectedText.length === 0) {
                showFlag('error', 'No text selected', 'Please select some text and try again', 'auto');
            } else {
                window.open(searchURL, '_blank');
            }
        });
    });
}
/**
 * This function registers two Tampermonkey exception menu command
 * Add Exception: adds the currently selected text to an exception list stored in local storage
 * Clear Exception: clears the exception list from local storage
 */
let exceptionKey = localStorage.getItem('exceptionKey')?.split(',') || [];
let notifyKey = [...exceptionKey];
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
                ? 'https://aspirepig-1251964320.cos.ap-shanghai.myqcloud.com/12221.wav'
                : 'https://aspirepig-1251964320.cos.ap-shanghai.myqcloud.com/alerts.wav';
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
            overdueTickets += `${issuekey}, `;
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
            body: `ticket: <strong>${overdueTickets}</strong><br>30 minutes have passed since the ticket's status changed, please handle it as soon as possible`,
            type: 'warning'
        });
    }
}

/**
 * This function checks for specific keywords within a string
 * Advises the user to double-check and contact L2 or TL if suspicious.
 * @param {Array} keywords - An array of strings containing the high risk keywords to check for
 */
function checkKeywords() {
    console.log('#### Code checkKeywords run ####');
    const keywords = ['keyword1', 'mimikatz', 'keyword3'];
    const strToCheck = $('#field-customfield_10219 > div:first-child > div:nth-child(2)').text().trim().toLowerCase();
    const matchedKeyword = keywords.find((keyword) => strToCheck.includes(keyword.toLowerCase()));
    if (matchedKeyword) {
        AJS.banner({
            body: `High Risk Keyword: <strong>${matchedKeyword}</strong><br>Please double-check it, and if it seems suspicious, contact L2 or TL.`
        });
    }
}

function checkATTCK() {
    const status = $('#status-val > span').text().trim();
    const attck = $('#rowForcustomfield_10220 > div > strong > label').text();
    if (status == 'Waiting for customer' && attck == '') {
        AJS.banner({ body: `The ATT&CK field is not filled in` });
    }
}

/**
 * This function initializes the edit notification functionality.
 * It adds click event listeners to the "Edit" button based on certain conditions,
 * and generates a specific HTML element for the edit notification.
 */
function editNotify(pageData) {
    console.log('#### Code editNotify run ####');

    function fetchOrgNotifydict() {
        GM_xmlhttpRequest({
            method: 'GET',
            url: 'https://aspirepig-1251964320.cos.ap-shanghai.myqcloud.com/notify.json',
            onload: function (response) {
                if (response.status === 200) {
                    const data = JSON.parse(response.responseText);
                    addClickListener(data);
                    generateNotify();
                } else {
                    console.error('Error fetching orgNotifydict:', response.status);
                }
            },
            onerror: function (error) {
                console.error('Error fetching orgNotifydict:', error);
            }
        });
    }
    fetchOrgNotifydict();

    // Add a click event listener to button
    function addClickListener(orgNotifydict) {
        // get button path
        function clickButton(click) {
            const buttonMap = {
                Edit: '#edit-issue',
                Resolve: '#action_id_761'
            };
            return buttonMap[click] || '';
        }

        // check all the condition
        function checkProperties(properties, valueFromPage) {
            // Iterate through all key-value pairs of the properties object
            for (const [property, value] of Object.entries(properties)) {
                // Converts the value of the valueFromPage property to an array
                const propertyValue = Array.isArray(valueFromPage[property])
                    ? valueFromPage[property]
                    : [valueFromPage[property]];
                // Check whether the value of the property is contained in the properties object
                if (!propertyValue.some((item) => item.includes(value))) {
                    return false;
                }
            }
            // Returns true if all properties match
            return true;
        }

        function processSection(keyFromPage) {
            // Gets data for a specific section of a configuration file
            const sectionConfig = orgNotifydict[keyFromPage];
            // Gets the value of a specific field extracted from web page
            const valueFromPage = pageData[keyFromPage];
            // Convert to Array List to handle mutil values from page
            const valueArray = Array.isArray(valueFromPage) ? valueFromPage : [valueFromPage];

            for (const value of valueArray) {
                // convert to Array List to handle mutil values from JSON
                const alerts = Array.isArray(sectionConfig[value]) ? sectionConfig[value] : [sectionConfig[value]];
                if (alerts[0] !== undefined) {
                    for (const alert of alerts) {
                        const { ticketname, message, properties, click } = alert;
                        const button = clickButton(click);

                        if (checkProperties(properties, pageData)) {
                            $(button).on('click', () => {
                                showFlag('warning', `${ticketname} ticket`, `${message}`, 'manual');
                            });
                        }
                    }
                }
            }
        }

        processSection('LogSourceDomain');
        processSection('LogSource');
        processSection('TicketAutoEscalate');
        processSection('Summary');
    }

    // add a element into toolbar
    function generateNotify() {
        const toolbar = $('.aui-toolbar2-primary');
        const element = $('<div id="generateEditnotify"></div>');
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
    const { rawLog, LogSourceDomain } = kwargs[0];
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
        'welab': 'https://welabbank.xdr.sg.paloaltonetworks.com/'
    };
    const orgNavigator = orgDict[LogSourceDomain];

    /**
     * Parse the relevant information from the raw log data
     * @param {Array} rawLog - An array of JSON strings representing the raw log data
     * @returns {Array} An array of objects containing the alert relevant information
     */
    function parseLog(rawLog) {
        const alertInfo = rawLog.reduce((acc, log) => {
            try {
                const { cortex_xdr } = JSON.parse(log);
                const { source, alert_id, name, description } = cortex_xdr;
                const isPANNGFW = source === 'PAN NGFW';
                const alert = { source, alert_id, name, description };
                if (isPANNGFW) {
                    const { action_local_ip, action_local_port, action_remote_ip, action_remote_port, action_pretty } =
                        cortex_xdr;
                    acc.push({
                        ...alert,
                        action_local_ip,
                        action_local_port,
                        action_remote_ip,
                        action_remote_port,
                        action_pretty
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
                        user_name
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

                    const actionPropsCount = countValidProperties(action_list)
                        ? countValidProperties(action_list) + 1
                        : 0;
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

                    acc.push({
                        ...alert,
                        host_name,
                        host_ip,
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
            return acc;
        }, []);
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
                action_file_macro_sha256
            } = info;
            if (source === 'PAN NGFW') {
                const desc = `Observed ${name}\nSrcip: ${action_local_ip}   Srcport: ${action_local_port}\nDstip: ${action_remote_ip}   Dstport: ${action_remote_port}\nAction: ${action_pretty}\n\nPlease help to verify if this activity is legitimate.\n`;
                alertDescriptions.push(desc);
            } else {
                const desc = `Observed ${description || name}\nHost: ${host_name}   IP: ${host_ip}\n${
                    action_local_ip ? 'action_local_ip: ' + action_local_ip + '\n' : ''
                }username: ${user_name}\ncmd: ${cmd}\nfilename: ${filename}\nfilepath: ${filepath}\naction: ${action_pretty}\n${
                    action_file_macro_sha256 ? 'macro file hash: ' + action_file_macro_sha256 + '\n' : ''
                }https://www.virustotal.com/gui/file/${
                    action_file_macro_sha256 || sha256
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
                        if (evidenceItem.entityType === 'File') {
                            const description = `filename:${evidenceItem.fileName}\nfilePath:${evidenceItem.filePath}\nsha1:${evidenceItem.sha1}\n`;
                            tmp.push(description);
                        }
                        if (evidenceItem.entityType === 'Process') {
                            const description = `cmd:${evidenceItem.processCommandLine}\naccount:${evidenceItem.accountName}\nsha1:${evidenceItem.sha1}\n`;
                            tmp.push(description);
                        }
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
            const desc = `Observed ${title}\nHost: ${computerDnsName}\nusername: ${userName}\n${extrainfo}\nPlease help to verify if it is legitimate.\n`;
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
                const eventEvidence = decodeHtml(logObj.event_evidence);
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

function CBAlertHandler(...kwargs) {
    console.log('#### Code CBAlertHandler run ####');
    const { rawLog, LogSourceDomain } = kwargs[0];
    // For Swire
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

    // For Jetco and other CEF log tickets
    function parseCefLog(rawLog) {
        function cefToJson(cefLog) {
            let json = {};
            let fields = cefLog.split(' ');

            for (let i = 0; i < fields.length; i++) {
                let field = fields[i].split('=');
                let key = field[0];
                let value = field.slice(1).join('=');

                if (value) {
                    value = value.replace(/\\\\=/g, '=').replace(/\\\\s/g, ' ');

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

    let alertInfo;
    if (LogSourceDomain == 'swireproperties') {
        alertInfo = parseLeefLog(rawLog);
    } else if (LogSourceDomain == 'jetco') {
        alertInfo = parseCefLog(rawLog);
    } else {
        alertInfo = '';
    }

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
                const alertExtraInfo = {
                    UserName: eventdata.subjectUserName,
                    TargetUserName: eventdata.targetUserName,
                    Member: eventdata.memberName,
                    Process: eventdata.newProcessName,
                    Command: eventdata.commandLine,
                    ParentProcess: eventdata.parentProcessName,
                    IP: eventdata.ipAddress,
                    ObjectDN: eventdata.objectDN,
                    ObjectGUID: eventdata.objectGUID
                };
                acc.push({ summary, alertHost, alertExtraInfo });
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
                action,
                devname,
                user,
                cfgattr,
                msg
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
                msg: msg
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
                    value = value.replace(/\\\\=/g, '=').replace(/\\\\s/g, ' ');

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

(function () {
    'use strict';

    registerSearchMenu();
    registerExceptionMenu();

    // Filter page: audio control registration and regular issues table update
    if (window.location.href.includes('filter=15200') && !window.location.href.includes('MSS')) {
        console.log('#### Code includes filter run ####');
        const NotifyControls = createNotifyControls();

        setInterval(() => {
            $('.aui-button.aui-button-primary.search-button').click();
            setTimeout(checkupdate(NotifyControls), 5000);
        }, 180000);
        setInterval(() => {
            notifyKey = [];
            window.location.href = 'https://caas.pwchk.com/issues/?filter=15200';
        }, 1800000);
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
                'carbonblack_cef': CBAlertHandler,
                'windows_eventchannel': WineventAlertHandler,
                'fortigate-firewall-v5': FortigateAlertHandler,
                'crowdstrike_cef': CSAlertHandler
            };
            const DecoderName = $('#customfield_10807-val').text().trim().toLowerCase();
            const handler = handlers[DecoderName];
            if (handler) {
                handler({ LogSourceDomain: LogSourceDomain, rawLog: rawLog, summary: summary });
            }
        }
    }, 3000);

    // Issue page: check Keywords and ATT&CK
    setInterval(() => {
        if ($('#issue-content').length && !$('.aui-banner-error').length) {
            console.log('#### Code Issue page: check Keywords ####');
            checkKeywords();
            checkATTCK();
        }
    }, 3000);

    // Issue page: Edit Notify
    setInterval(() => {
        const LogSourceDomain = $('#customfield_10223-val').text().trim();
        const Labels = $('.labels-wrap .labels li a span').text();
        const LogSource = $('#customfield_10204-val').text().trim();
        const TicketAutoEscalate = $('#customfield_12202-val').text().trim();
        const Status = $('#status-val > span').text().trim();
        const RawLog = $('#field-customfield_10219 > div:first-child > div:nth-child(2)').text().trim().split('\n');
        const Summary = $('#summary-val').text().trim();
        const pageData = { LogSourceDomain, Labels, LogSource, TicketAutoEscalate, Status, RawLog, Summary };
        // If it pops up once, it will not be reminded again
        if ($('#issue-content').length && !$('#generateEditnotify').length) {
            console.log('#### Code Issue page: Edit Notify ####');
            editNotify(pageData);
        }
    }, 3000);
})();
