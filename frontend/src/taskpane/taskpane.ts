/*
 * Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
 * See LICENSE in the project root for license information.
 */

/* global document, Office */

Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    document.getElementById("sideload-msg").style.display = "none";
    document.getElementById("app-body").style.display = "flex";
    document.getElementById("run").onclick = run;
  }
});

export async function run() {
  /**
   * Insert your Outlook code here
   */

  const item = Office.context.mailbox.item;
  
  try {
    // Collect email data
    const emailData: any = {
      subject: item.subject || "",
      body: "",
      from: "",
      to: "",
      cc: [],
      bcc: [],
      reply_to: "",
      date: "",
      attachments: [],
      headers: {}
    };

    // Get body content
    if (item.body) {
      item.body.getAsync(Office.CoercionType.Text, (result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          emailData.body = result.value;
          sendEmailToServer(emailData, item);
        } else {
          sendEmailToServer(emailData, item);
        }
      });
    } else {
      sendEmailToServer(emailData, item);
    }
  } catch (error) {
    console.error("Error collecting email data:", error);
    alert("Błąd podczas zbierania danych emaila. Email jest niepewny.");
  }
}

function sendEmailToServer(emailData: any, item: Office.ItemRead) {
  try {
    // Get email addresses
    if (item.from && item.from.emailAddress) {
      emailData.from = item.from.emailAddress;
    }
    
    // Get 'to' addresses - take first one as string
    if (item.to && item.to.length > 0) {
      const toAddresses = item.to.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
      emailData.to = toAddresses.length > 0 ? toAddresses[0] : "";
    }
    
    // Get CC addresses
    if (item.cc && item.cc.length > 0) {
      emailData.cc = item.cc.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
    }
    
    // Get BCC addresses
    if (item.bcc && item.bcc.length > 0) {
      emailData.bcc = item.bcc.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
    }
    
    // Get reply-to
    if (item.replyTo && item.replyTo.length > 0) {
      emailData.reply_to = item.replyTo[0].emailAddress || "";
    }
    
    // Get date
    if (item.dateTimeCreated) {
      emailData.date = item.dateTimeCreated.toISOString();
    }
    
    // Get attachments
    if (item.attachments && item.attachments.length > 0) {
      emailData.attachments = item.attachments.map((att: Office.AttachmentDetails) => ({
        filename: att.name || "",
        size: att.size || 0,
        content_type: att.contentType || ""
      }));
    }
    
    // Get headers if available
    if (item.internetHeaders) {
      item.internetHeaders.getAllAsync((result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          emailData.headers = result.value || {};
          performRequest(emailData);
        } else {
          performRequest(emailData);
        }
      });
    } else {
      performRequest(emailData);
    }
  } catch (error) {
    console.error("Error processing email data:", error);
    alert("Błąd podczas przetwarzania danych emaila. Email jest niepewny.");
  }
}

async function performRequest(emailData: any) {
  try {
    const response = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(emailData)
    });

    if (!response.ok) {
      let errorMsg = "";
      if (response.status === 500) {
        errorMsg = "Server 500 - Email jest niepewny";
      } else {
        errorMsg = `Błąd serwera (${response.status}) - Email jest niepewny`;
      }
      alert(errorMsg);
      displayError(errorMsg);
      return;
    }

    const result = await response.json();
    console.log("Server response:", result);
    
    // Display analysis result
    displayAnalysisResult(result);
    
  } catch (error: any) {
    console.error("Error sending request to server:", error);
    // Check if it's a network error (connection refused, etc.)
    if (error.message && (error.message.includes("Failed to fetch") || error.message.includes("NetworkError"))) {
      displayError("Nie udało się połączyć z serwerem. Email jest niepewny.");
      alert("Nie udało się połączyć z serwerem. Email jest niepewny.");
    } else {
      displayError("Nie udało się wysłać zapytania na serwer. Email jest niepewny.");
      alert("Nie udało się wysłać zapytania na serwer. Email jest niepewny.");
    }
  }
}

function displayAnalysisResult(result: any) {
  const resultContainer = document.getElementById("analysis-result");
  if (!resultContainer) return;

  // Check various possible response formats from the server
  const isPhishing = result.is_phishing !== undefined ? result.is_phishing :
                     result.phishing !== undefined ? result.phishing :
                     result.isPhishing !== undefined ? result.isPhishing :
                     result.result === "phishing" ? true :
                     result.result === "safe" ? false :
                     result.status === "phishing" ? true :
                     result.status === "safe" ? false :
                     false;

  const confidence = result.confidence || result.confidence_score || null;
  const message = result.message || result.description || "";

  // Create result HTML
  let html = '<div style="padding: 15px; border-radius: 5px; margin-top: 10px;">';
  
  if (isPhishing) {
    html += '<div style="background-color: #fef2f2; border: 2px solid #dc2626; padding: 15px; border-radius: 5px;">';
    html += '<h3 style="color: #dc2626; margin-top: 0;">⚠️ TEN EMAIL JEST PHISHINGOWY!</h3>';
    html += '<p style="color: #991b1b; font-weight: bold;">Nie otwieraj załączników i nie klikaj w linki w tym emailu.</p>';
  } else {
    html += '<div style="background-color: #f0fdf4; border: 2px solid #16a34a; padding: 15px; border-radius: 5px;">';
    html += '<h3 style="color: #16a34a; margin-top: 0;">✅ TEN EMAIL NIE JEST PHISHINGOWY</h3>';
    html += '<p style="color: #166534;">Email wygląda na bezpieczny.</p>';
  }

  if (confidence !== null) {
    html += `<p style="margin-top: 10px; color: #666;">Pewność analizy: ${(confidence * 100).toFixed(1)}%</p>`;
  }

  if (message) {
    html += `<p style="margin-top: 10px; color: #666;">${message}</p>`;
  }

  html += '</div></div>';

  resultContainer.innerHTML = html;
}

function displayError(errorMessage: string) {
  const resultContainer = document.getElementById("analysis-result");
  if (!resultContainer) return;

  let html = '<div style="padding: 15px; border-radius: 5px; margin-top: 10px;">';
  html += '<div style="background-color: #fff7ed; border: 2px solid #f59e0b; padding: 15px; border-radius: 5px;">';
  html += `<h3 style="color: #f59e0b; margin-top: 0;">⚠️ Błąd analizy</h3>`;
  html += `<p style="color: #92400e;">${errorMessage}</p>`;
  html += '</div></div>';

  resultContainer.innerHTML = html;
}
