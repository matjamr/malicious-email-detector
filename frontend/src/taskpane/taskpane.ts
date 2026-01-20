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
    
    // Automatycznie uruchom analizę po otwarciu panelu, jeśli jest otwarty email
    // Sprawdzamy czy email jest dostępny i czy to nie jest pierwsze załadowanie (sideload message)
    try {
      if (Office.context.mailbox.item) {
        // Opóźnienie, żeby UI się załadowało
        setTimeout(() => {
          run();
        }, 500);
      }
    } catch (e) {
      console.error("Error auto-running analysis:", e);
    }
  }
});

export async function run() {
  const loadingIndicator = document.getElementById("loading-indicator");
  const resultContainer = document.getElementById("analysis-result");
  
  if (loadingIndicator) loadingIndicator.style.display = "block";
  if (resultContainer) resultContainer.innerHTML = "";

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
    await new Promise<void>((resolve) => {
      if (item.body) {
        item.body.getAsync(Office.CoercionType.Text, (result) => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            emailData.body = result.value;
          }
          resolve();
        });
      } else {
        resolve();
      }
    });

    sendEmailToServer(emailData, item);
  } catch (error) {
    console.error("Error collecting email data:", error);
    if (loadingIndicator) loadingIndicator.style.display = "none";
    displayError("Błąd podczas zbierania danych emaila.");
  }
}

function sendEmailToServer(emailData: any, item: Office.ItemRead) {
  try {
    // Get email addresses
    if (item.from && item.from.emailAddress) {
      emailData.from = item.from.emailAddress;
    }
    
    if (item.to && item.to.length > 0) {
      const toAddresses = item.to.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
      emailData.to = toAddresses.length > 0 ? toAddresses[0] : "";
    }
    
    if (item.cc && item.cc.length > 0) {
      emailData.cc = item.cc.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
    }
    
    if (item.bcc && item.bcc.length > 0) {
      emailData.bcc = item.bcc.map((addr: Office.EmailAddressDetails) => addr.emailAddress || "").filter(addr => addr);
    }
    
    if (item.replyTo && item.replyTo.length > 0) {
      emailData.reply_to = item.replyTo[0].emailAddress || "";
    }
    
    if (item.dateTimeCreated) {
      emailData.date = item.dateTimeCreated.toISOString();
    }
    
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
        }
        performRequest(emailData);
      });
    } else {
      performRequest(emailData);
    }
  } catch (error) {
    console.error("Error processing email data:", error);
    const loadingIndicator = document.getElementById("loading-indicator");
    if (loadingIndicator) loadingIndicator.style.display = "none";
    displayError("Błąd podczas przetwarzania danych emaila.");
  }
}

async function performRequest(emailData: any) {
  const loadingIndicator = document.getElementById("loading-indicator");
  
  try {
    const response = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(emailData)
    });

    if (loadingIndicator) loadingIndicator.style.display = "none";

    if (!response.ok) {
      let errorMsg = `Błąd serwera (${response.status})`;
      displayError(errorMsg);
      return;
    }

    const result = await response.json();
    console.log("Server response:", result);
    
    // Display analysis result
    displayAnalysisResult(result);
    
  } catch (error: any) {
    console.error("Error sending request to server:", error);
    if (loadingIndicator) loadingIndicator.style.display = "none";
    
    if (error.message && (error.message.includes("Failed to fetch") || error.message.includes("NetworkError"))) {
      displayError("Nie udało się połączyć z serwerem. Upewnij się, że backend działa na http://127.0.0.1:5000");
    } else {
      displayError("Nie udało się wysłać zapytania na serwer.");
    }
  }
}

function displayAnalysisResult(result: any) {
  const resultContainer = document.getElementById("analysis-result");
  if (!resultContainer) return;

  const overallScore = result.overall_score || 0;
  const content = result.content_analysis || {};
  const sender = result.sender_analysis || {};
  const recipient = result.recipient_analysis || {};
  const attachment = result.attachment_analysis || {};
  const security = result.security_analysis || {};
  const metadata = result.metadata || {};

  // Determine risk level and colors
  let riskLevel = "low";
  let riskColor = "#16a34a"; // green
  let riskBgColor = "#f0fdf4";
  let riskBorderColor = "#16a34a";
  let riskText = "Bezpieczny";
  let riskMessage = "Email wygląda na bezpieczny.";

  if (overallScore >= 70) {
    riskLevel = "high";
    riskColor = "#dc2626"; // red
    riskBgColor = "#fef2f2";
    riskBorderColor = "#dc2626";
    riskText = "Wysokie Ryzyko";
    riskMessage = "Nie otwieraj załączników i nie klikaj w linki!";
  } else if (overallScore >= 40) {
    riskLevel = "medium";
    riskColor = "#f59e0b"; // orange
    riskBgColor = "#fff7ed";
    riskBorderColor = "#f59e0b";
    riskText = "Średnie Ryzyko";
    riskMessage = "Sprawdź email dokładnie przed otwarciem.";
  }

  let html = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
      <!-- Overall Score Card -->
      <div style="background: ${riskBgColor}; 
                  border: 1px solid ${riskBorderColor}; 
                  border-radius: 8px; 
                  padding: 24px; 
                  margin-bottom: 20px;
                  box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <div style="text-align: center;">
          <h2 style="color: ${riskColor}; margin: 0 0 12px 0; font-size: 20px; font-weight: 600; letter-spacing: -0.3px;">${riskText}</h2>
          <div style="font-size: 32px; font-weight: 300; color: ${riskColor}; margin-bottom: 16px;">
            ${overallScore}<span style="font-size: 18px; color: #666; margin-left: 4px;">/100</span>
          </div>
          <div style="width: 100%; height: 6px; background-color: #e5e7eb; border-radius: 3px; overflow: hidden; margin-bottom: 12px;">
            <div style="width: ${overallScore}%; height: 100%; background-color: ${riskColor}; transition: width 0.3s ease;"></div>
          </div>
          <p style="color: #666; margin: 0; font-size: 13px; line-height: 1.5;">
            ${riskMessage}
          </p>
        </div>
      </div>

      <!-- Security Indicators -->
      ${security.suspicious_indicators && security.suspicious_indicators.length > 0 ? `
      <div style="background-color: #fff; border-left: 3px solid ${riskColor}; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: ${riskColor}; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Wykryte Zagrożenia
        </h3>
        <ul style="margin: 0; padding-left: 20px; color: #374151; font-size: 14px; line-height: 1.6;">
          ${security.suspicious_indicators.map((indicator: string) => `<li style="margin-bottom: 6px;">${indicator}</li>`).join('')}
        </ul>
      </div>
      ` : ''}

      <!-- Content Analysis -->
      <div style="background-color: #fff; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Analiza Treści
        </h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 14px;">
          ${content.subject_has_suspicious_keywords ? `
          <div style="padding: 10px; background-color: #fef2f2; border-radius: 4px;">
            <div style="font-weight: 600; color: #dc2626; margin-bottom: 4px; font-size: 13px;">Podejrzane słowa w temacie</div>
            <div style="color: #666; font-size: 13px;">${content.subject_suspicious_keywords?.join(', ') || 'Wykryto'}</div>
          </div>
          ` : ''}
          ${content.body_has_suspicious_keywords ? `
          <div style="padding: 10px; background-color: #fef2f2; border-radius: 4px;">
            <div style="font-weight: 600; color: #dc2626; margin-bottom: 4px; font-size: 13px;">Podejrzane słowa w treści</div>
            <div style="color: #666; font-size: 13px;">${content.body_suspicious_keywords?.join(', ') || 'Wykryto'}</div>
          </div>
          ` : ''}
          ${content.subject_has_urls ? `
          <div style="padding: 10px; background-color: #fff7ed; border-radius: 4px;">
            <div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px; font-size: 13px;">URL w temacie</div>
            <div style="color: #666; font-size: 12px; word-break: break-all;">${content.subject_urls?.slice(0, 2).join(', ') || 'Wykryto'}</div>
          </div>
          ` : ''}
          ${content.body_has_urls ? `
          <div style="padding: 10px; background-color: #fff7ed; border-radius: 4px;">
            <div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px; font-size: 13px;">URL w treści</div>
            <div style="color: #666; font-size: 12px;">Znaleziono ${content.body_urls?.length || 0} link(ów)</div>
          </div>
          ` : ''}
        </div>
        ${content.subject_uppercase_ratio > 0.5 ? `
        <div style="margin-top: 12px; padding: 10px; background-color: #fff7ed; border-radius: 4px;">
          <div style="font-weight: 600; color: #f59e0b; font-size: 13px;">Wysoki procent wielkich liter w temacie (${(content.subject_uppercase_ratio * 100).toFixed(0)}%)</div>
        </div>
        ` : ''}
      </div>

      <!-- Sender Analysis -->
      <div style="background-color: #fff; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Analiza Nadawcy
        </h3>
        <div style="font-size: 14px;">
          <div style="margin-bottom: 8px;">
            <span style="font-weight: 600; color: #374151;">Email:</span>
            <span style="color: #666; margin-left: 8px;">${sender.from || 'Brak'}</span>
            ${sender.from_valid ? '<span style="color: #16a34a; margin-left: 8px;">✓</span>' : '<span style="color: #dc2626; margin-left: 8px;">✗</span>'}
          </div>
          ${sender.from_domain ? `
          <div style="margin-bottom: 8px;">
            <span style="font-weight: 600; color: #374151;">Domena:</span>
            <span style="color: #666; margin-left: 8px;">${sender.from_domain}</span>
          </div>
          ` : ''}
          ${sender.reply_to_different ? `
          <div style="padding: 10px; background-color: #fef2f2; border-radius: 4px; margin-top: 8px;">
            <div style="font-weight: 600; color: #dc2626; font-size: 13px;">Reply-To różni się od nadawcy</div>
            <div style="color: #666; font-size: 12px; margin-top: 4px;">Reply-To: ${sender.reply_to || 'Brak'}</div>
          </div>
          ` : ''}
          ${sender.has_display_name && sender.display_name ? `
          <div style="margin-top: 8px;">
            <span style="font-weight: 600; color: #374151;">Nazwa wyświetlana:</span>
            <span style="color: #666; margin-left: 8px;">${sender.display_name}</span>
          </div>
          ` : ''}
        </div>
      </div>

      <!-- Attachment Analysis -->
      ${attachment.count > 0 ? `
      <div style="background-color: #fff; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Analiza Załączników (${attachment.count})
        </h3>
        ${attachment.has_executables ? `
        <div style="padding: 10px; background-color: #fef2f2; border-radius: 4px; margin-bottom: 12px;">
          <div style="font-weight: 600; color: #dc2626; font-size: 13px;">Wykryto pliki wykonywalne</div>
          <div style="color: #666; font-size: 12px; margin-top: 4px;">Rozszerzenia: ${attachment.executable_extensions?.join(', ') || 'Wykryto'}</div>
        </div>
        ` : ''}
        ${attachment.has_scripts ? `
        <div style="padding: 10px; background-color: #fef2f2; border-radius: 4px; margin-bottom: 12px;">
          <div style="font-weight: 600; color: #dc2626; font-size: 13px;">Wykryto pliki skryptów</div>
          <div style="color: #666; font-size: 12px; margin-top: 4px;">Rozszerzenia: ${attachment.script_extensions?.join(', ') || 'Wykryto'}</div>
        </div>
        ` : ''}
        ${attachment.suspicious_extensions && attachment.suspicious_extensions.length > 0 ? `
        <div style="padding: 10px; background-color: #fff7ed; border-radius: 4px; margin-bottom: 12px;">
          <div style="font-weight: 600; color: #f59e0b; font-size: 13px;">Podejrzane rozszerzenia</div>
          <div style="color: #666; font-size: 12px; margin-top: 4px;">${attachment.suspicious_extensions.join(', ')}</div>
        </div>
        ` : ''}
        <div style="font-size: 14px; color: #666;">
          <div>Całkowity rozmiar: ${formatBytes(attachment.total_size || 0)}</div>
        </div>
        ${attachment.files && attachment.files.length > 0 ? `
        <div style="margin-top: 12px;">
          <div style="font-weight: 600; color: #374151; margin-bottom: 8px;">Pliki:</div>
          ${attachment.files.map((file: any) => `
            <div style="padding: 8px; background-color: #f9fafb; border-radius: 4px; margin-bottom: 4px; font-size: 12px;">
              <div style="font-weight: 500;">${file.filename || 'Nieznany'}</div>
              <div style="color: #666; font-size: 11px;">${formatBytes(file.size || 0)} • ${file.content_type || 'Nieznany typ'}</div>
            </div>
          `).join('')}
        </div>
        ` : ''}
      </div>
      ` : ''}

      <!-- Recipient Analysis -->
      ${recipient.total_recipients > 0 ? `
      <div style="background-color: #fff; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Odbiorcy
        </h3>
        <div style="font-size: 14px; color: #666;">
          <div style="margin-bottom: 4px;">Do: ${recipient.to_count || 0}</div>
          ${recipient.has_cc ? `<div style="margin-bottom: 4px;">CC: ${recipient.cc_count || 0}</div>` : ''}
          ${recipient.has_bcc ? `<div style="margin-bottom: 4px;">BCC: ${recipient.bcc_count || 0}</div>` : ''}
          <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #e5e7eb;">
            <div>Unikalne domeny: ${recipient.unique_domain_count || 0}</div>
          </div>
        </div>
      </div>
      ` : ''}

      <!-- Security Flags -->
      ${security.flags && security.flags.length > 0 ? `
      <div style="background-color: #fff; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <h3 style="margin: 0 0 12px 0; color: #1f2937; font-size: 15px; font-weight: 600; letter-spacing: -0.2px;">
          Flagi Bezpieczeństwa
        </h3>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
          ${security.flags.map((flag: string) => `
            <span style="padding: 6px 12px; background-color: #fef2f2; color: #dc2626; border-radius: 6px; font-size: 12px; font-weight: 500;">
              ${flag}
            </span>
          `).join('')}
        </div>
      </div>
      ` : ''}
    </div>
  `;

  resultContainer.innerHTML = html;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function displayError(errorMessage: string) {
  const resultContainer = document.getElementById("analysis-result");
  if (!resultContainer) return;

  let html = `
    <div style="background-color: #fff7ed; border: 1px solid #f59e0b; border-radius: 6px; padding: 20px; margin-top: 20px;">
      <h3 style="color: #f59e0b; margin: 0 0 8px 0; font-size: 16px; font-weight: 600; letter-spacing: -0.2px;">Błąd analizy</h3>
      <p style="color: #92400e; margin: 0; font-size: 14px; line-height: 1.5;">${errorMessage}</p>
    </div>
  `;

  resultContainer.innerHTML = html;
}
