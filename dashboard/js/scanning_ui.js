const progressBar = document.getElementById("progressBar");
const scanText = document.getElementById("scanText");

let progress = 0;

function simulateScan(){

    progress = 0;

    scanText.innerText = "Scanning USB Device...";

    const interval = setInterval(()=>{

        progress += 10;

        progressBar.style.width = progress + "%";

        if(progress >= 100){

            clearInterval(interval);

            scanText.innerText = "Scan Completed";

        }

    },400);

}

document.addEventListener("deviceDetected",simulateScan);
