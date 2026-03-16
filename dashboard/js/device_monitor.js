const API = "http://localhost:5000";

async function loadDevices() {

    try {

        const response = await fetch(API + "/devices");

        const data = await response.json();

        const table = document.querySelector("#deviceTable tbody");

        table.innerHTML = "";

        data.devices.forEach(device => {

            const row = document.createElement("tr");

            row.innerHTML = `

            <td>${device.device_node}</td>
            <td>${device.vendor_id}</td>
            <td>${device.product}</td>
            <td>${device.serial_number}</td>

            `;

            table.appendChild(row);

        });

    }

    catch(error){

        console.log("Device API error", error);

    }

}

setInterval(loadDevices,3000);

loadDevices();
