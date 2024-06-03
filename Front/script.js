String.prototype.capitalizeWords = function () {
    return this.replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
};

function addElement(tagName, innerHTML, parent) {
    const element = document.createElement(tagName);
    element.innerHTML = innerHTML;
    parent.appendChild(element);
    return element;
}

function addImage(data, container) {
    addElement("hr", "", container);
    const imageHTML = `<img style="height: 100%; width:100%;" src="data:image/png;base64,${data}"\\>`;
    addElement("div", imageHTML, container);
}

function addText(key, data, dictionary, container) {
    addElement("hr", "", container);
    let value = Array.isArray(data) ? `${key.capitalizeWords()}: ${data.map(element => `<br>${element}`).join('')}`
                                     : `${dictionary[key] || key.capitalizeWords()}: ${data}`;
    addElement("div", value, container);
}

function addMap(latitude, longitude, container) {
    addElement("hr", "", container);
    const mapContainer = addElement("div", "", container);
    mapContainer.setAttribute("id", "map");
    mapContainer.setAttribute("style", "height:40vh; width:100%;");

    const map = L.map('map').setView([latitude, longitude], 10);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
    L.marker([latitude, longitude]).addTo(map);
}

function displayDataElements(data, container, dictionary, ignoredItems) {
    for (const key of Object.keys(data)) {
        console.log(key);
        if (key === 'screenshot') {
            addImage(data[key], container);
        } else if (!ignoredItems.includes(key)) {
            if (key === "country_name") {
                addMap(data["latitude"], data["longitude"], container);
            } else {
                addText(key, data[key], dictionary, container);
            }
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const largeJsonScript = document.getElementById('large-json-data');
    const largeJsonData = JSON.parse(largeJsonScript.getAttribute('data-large-json'));

    toolsConfig.forEach((config) => {
        const container = document.querySelector(config.containerSelector);
        displayDataElements(largeJsonData[config.dataKey], container, config.dictionary, config.ignoredItems);
    });
});