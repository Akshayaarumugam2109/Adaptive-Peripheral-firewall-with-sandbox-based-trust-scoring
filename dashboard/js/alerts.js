const ALERT_API = "http://localhost:5000/alerts";

async function loadAlerts(){

    try{

        const response = await fetch(ALERT_API);

        const data = await response.json();

        const alertList = document.getElementById("alertList");

        alertList.innerHTML = "";

        data.alerts.forEach(alert=>{

            const li = document.createElement("li");

            li.innerText =
            `${alert.alert_type} : ${alert.description}`;

            alertList.appendChild(li);

        });

    }

    catch(error){

        console.log("Alert API error",error);

    }

}

setInterval(loadAlerts,3000);

loadAlerts();
