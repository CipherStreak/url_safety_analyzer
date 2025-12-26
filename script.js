// Navigation
function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    document.getElementById(pageId).classList.add('active');
    
    // Update nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-page') === pageId) {
            btn.classList.add('active');
        }
    });
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleMobileMenu() {
    const mobileNav = document.getElementById('mobileNav');
    mobileNav.classList.toggle('active');
}

// Trusted domains list
const trustedDomains = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
    'amazon.com', 'ebay.com', 'paypal.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'spotify.com', 'zoom.us', 'dropbox.com', 'adobe.com',
    'salesforce.com', 'oracle.com', 'ibm.com', 'intel.com', 'cisco.com',
    'mozilla.org', 'wordpress.org', 'medium.com', 'twitch.tv', 'discord.com'
];

// Suspicious TLDs
const suspiciousTLDs = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click',
    '.link', '.download', '.stream', '.racing', '.accountant', '.trade',
    '.science', '.party', '.gdn', '.loan', '.cricket', '.win', '.bid',
    '.review', '.faith', '.date', '.webcam', '.men'
];

// Common typosquatting patterns for popular sites
const typosquattingPatterns = {
    'microsoft': ['rnicrosoft', 'microsft', 'micros0ft', 'rnicr0soft', 'mlcrosoft', 'rnicrosofl'],
    'google': ['googie', 'gooogle', 'g00gle', 'qoogle', 'goog1e', 'gogle'],
    'facebook': ['facebo0k', 'facebok', 'faceb00k', 'faceobok', 'facebοοk'],
    'paypal': ['paypai', 'paypa1', 'paypai', 'papal', 'pay-pal', 'paypa'],
    'amazon': ['arnaz0n', 'arnazon', 'amaz0n', 'amazοn', 'amozon'],
    'apple': ['app1e', 'appie', 'appl3', 'αpple'],
    'netflix': ['netfl1x', 'netflixx', 'netfIix', 'netflex'],
    'instagram': ['instagrarn', 'instagr4m', 'lnstagram', 'instaqram'],
    'linkedin': ['linkedln', 'link3din', 'Iinkedin', 'linkedinc'],
    'twitter': ['twiter', 'twtter', 'twltter', 'twittter']
};

// Known malicious keywords
const maliciousKeywords = [
    'phishing', 'malware', 'virus', 'scam', 'hack', 'fraud', 'fake',
    'suspended', 'verify', 'account-update', 'secure-login', 'confirm-identity',
    'free-prize', 'winner', 'claim-now', 'urgent-action', 'limited-time'
];

// URL Analysis Function
function analyzeURL() {
    const input = document.getElementById('urlInput').value.trim();
    const resultsDiv = document.getElementById('results');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (!input) {
        alert('Please enter a URL to analyze');
        return;
    }
    
    // Show analyzing state
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span>🔄</span> Analyzing...';
    
    // Simulate analysis delay
    setTimeout(() => {
        const result = performAnalysis(input);
        displayResults(result);
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '<span>🔍</span> Analyze';
    }, 1500);
}

function performAnalysis(url) {
    let score = 5;
    let status = 'safe';
    const threats = [];
    let recommendation = '';
    
    try {
        // Normalize URL
        let testUrl = url.toLowerCase();
        if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
            testUrl = 'https://' + testUrl;
        }
        
        const urlObj = new URL(testUrl);
        const hostname = urlObj.hostname.replace('www.', '');
        const domain = hostname.split('.').slice(-2).join('.');
        const fullPath = hostname + urlObj.pathname + urlObj.search;
        
        // Check 1: IP Address instead of domain
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            score -= 2;
            threats.push('Using IP address instead of domain name');
        }
        
        // Check 2: Suspicious TLDs
        for (const tld of suspiciousTLDs) {
            if (hostname.endsWith(tld)) {
                score -= 2;
                threats.push(`Suspicious domain extension (${tld})`);
                break;
            }
        }
        
        // Check 3: Typosquatting detection
        for (const [brand, variants] of Object.entries(typosquattingPatterns)) {
            for (const variant of variants) {
                if (hostname.includes(variant)) {
                    score -= 3;
                    threats.push(`Possible typosquatting attempt (similar to ${brand}.com)`);
                    break;
                }
            }
        }
        
        // Check 4: Look for legitimate brand names with wrong TLD
        const legitimateBrands = Object.keys(typosquattingPatterns);
        for (const brand of legitimateBrands) {
            if (hostname.includes(brand) && !trustedDomains.includes(domain)) {
                // Check if it's trying to impersonate
                const legitDomain = brand + '.com';
                if (hostname !== legitDomain && hostname.includes(brand)) {
                    score -= 2;
                    threats.push(`Suspicious use of brand name "${brand}"`);
                }
            }
        }
        
        // Check 5: Excessive hyphens or numbers
        const hyphenCount = (hostname.match(/-/g) || []).length;
        const numberCount = (hostname.match(/\d/g) || []).length;
        
        if (hyphenCount > 2) {
            score -= 1;
            threats.push('Excessive hyphens in domain name');
        }
        
        if (numberCount > 3) {
            score -= 1;
            threats.push('Excessive numbers in domain name');
        }
        
        // Check 6: Malicious keywords
        for (const keyword of maliciousKeywords) {
            if (fullPath.includes(keyword)) {
                score -= 2;
                threats.push(`Suspicious keyword detected: "${keyword}"`);
                break;
            }
        }
        
        // Check 7: Very long domain name
        if (hostname.length > 40) {
            score -= 1;
            threats.push('Unusually long domain name');
        }
        
        // Check 8: Subdomain depth
        const subdomainLevels = hostname.split('.').length - 2;
        if (subdomainLevels > 2) {
            score -= 1;
            threats.push('Multiple subdomains detected');
        }
        
        // Check 9: No HTTPS
        if (!testUrl.startsWith('https://')) {
            score -= 1;
            threats.push('Not using secure HTTPS protocol');
        }
        
        // Check 10: Trusted domain check
        let isTrusted = false;
        for (const trusted of trustedDomains) {
            if (domain === trusted || hostname === trusted) {
                isTrusted = true;
                break;
            }
        }
        
        if (isTrusted) {
            score = 5;
            threats.length = 0;
            threats.push('Verified trusted domain');
            threats.push('Valid SSL certificate');
            threats.push('No known security threats');
        }
        
        // Ensure score is between 1 and 5
        score = Math.max(1, Math.min(5, score));
        
        // Determine status based on score
        if (score <= 2) {
            status = 'harmful';
            recommendation = '⚠️ DANGER: Do not visit this site! It shows multiple signs of being malicious, including possible phishing attempts or typosquatting. This site may steal your personal information, passwords, or install malware on your device.';
        } else if (score === 3) {
            status = 'neutral';
            recommendation = '⚠️ CAUTION: This site has some suspicious characteristics. We cannot verify its safety. Avoid entering any personal information, passwords, or payment details. If you must visit, ensure you have updated security software.';
        } else {
            status = 'safe';
            recommendation = '✅ SAFE: This site appears to be legitimate and safe to visit. However, always remain cautious about sharing personal information online and verify you are on the correct website.';
            if (threats.length === 0) {
                threats.push('No suspicious patterns detected');
                threats.push('Domain appears legitimate');
                threats.push('Standard security indicators present');
            }
        }
        
    } catch (error) {
        score = 1;
        status = 'harmful';
        threats.push('Invalid URL format');
        threats.push('Cannot verify domain authenticity');
        recommendation = '⚠️ ERROR: The URL you entered appears to be invalid or malformed. Please check the URL and try again.';
    }
    
    return {
        url: url,
        score: score,
        status: status,
        threats: threats,
        recommendation: recommendation
    };
}

function displayResults(result) {
    const resultsDiv = document.getElementById('results');
    
    const statusEmoji = {
        'harmful': '🔴',
        'neutral': '🟡',
        'safe': '🟢'
    };
    
    const statusText = {
        'harmful': 'Harmful',
        'neutral': 'Neutral',
        'safe': 'Safe'
    };
    
    let starsHTML = '';
    for (let i = 1; i <= 5; i++) {
        const filled = i <= result.score;
        const starClass = filled ? `star filled ${result.status}` : 'star';
        starsHTML += `<span class="${starClass}" style="animation-delay: ${i * 0.1}s">⭐</span>`;
    }
    
    let threatsHTML = '';
    result.threats.forEach(threat => {
        threatsHTML += `
            <div class="threat-item">
                <span class="threat-dot ${result.status}"></span>
                <span>${threat}</span>
            </div>
        `;
    });
    
    resultsDiv.innerHTML = `
        <div class="result-header">
            <div class="status-badge ${result.status}">
                ${statusEmoji[result.status]} ${statusText[result.status]}
            </div>
            <div class="stars">${starsHTML}</div>
            <div class="score-text">${result.score}/5 Safety Score</div>
        </div>
        
        <div class="result-details">
            <div class="detail-section">
                <h4>URL Analyzed:</h4>
                <div class="detail-content">${result.url}</div>
            </div>
            
            <div class="detail-section">
                <h4>Threat Analysis:</h4>
                <div class="detail-content">
                    <div class="threat-list">${threatsHTML}</div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4>Recommendation:</h4>
                <div class="detail-content">${result.recommendation}</div>
            </div>
        </div>
    `;
    
    resultsDiv.classList.remove('hidden');
}

// Globe Animation
const threatURLs = {
    high: [
        'phishing-bank-verify.tk',
        'secure-paypal-login.ml',
        'rnicrosoft-update.xyz',
        'verify-account-amazon.ga',
        'suspended-account.link',
        'urgent-security-alert.click',
        'claim-prize-winner.work'
    ],
    medium: [
        'unknown-shopping-site.top',
        'unverified-deals.racing',
        'suspicious-download.stream',
        'questionable-offers.trade',
        'untrusted-source.science'
    ],
    low: [
        'google.com',
        'github.com',
        'stackoverflow.com',
        'wikipedia.org',
        'mozilla.org'
    ]
};

function generateAttack() {
    const globe = document.querySelector('.globe-sphere');
    const threatList = document.getElementById('threatList');
    
    if (!globe || !threatList) return;
    
    const threatTypes = ['high', 'medium', 'low'];
    const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    const urls = threatURLs[threat];
    const url = urls[Math.floor(Math.random() * urls.length)];
    
    const colors = {
        high: '#ef4444',
        medium: '#f59e0b',
        low: '#10b981'
    };
    
    // Create attack marker on globe
    const marker = document.createElement('div');
    marker.className = 'attack-marker';
    marker.style.background = colors[threat];
    marker.style.boxShadow = `0 0 20px ${colors[threat]}`;
    marker.style.left = Math.random() * 90 + 5 + '%';
    marker.style.top = Math.random() * 90 + 5 + '%';
    globe.appendChild(marker);
    
    setTimeout(() => marker.remove(), 3000);
    
    // Add to threat feed
    const threatItem = document.createElement('div');
    threatItem.className = 'threat-feed-item';
    threatItem.innerHTML = `
        <div class="threat-level" style="color: ${colors[threat]}">
            <span class="threat-level-dot" style="background: ${colors[threat]}"></span>
            ${threat} threat
        </div>
        <div class="threat-url">${url}</div>
    `;
    
    threatList.insertBefore(threatItem, threatList.firstChild);
    
    // Keep only last 10 items
    while (threatList.children.length > 10) {
        threatList.removeChild(threatList.lastChild);
    }
}

// Start globe animation
setInterval(generateAttack, 2000);

// Feedback Form
let selectedRating = 0;

function setRating(rating) {
    selectedRating = rating;
    const stars = document.querySelectorAll('.star-rating .star');
    stars.forEach((star, index) => {
        if (index < rating) {
            star.classList.add('active');
        } else {
            star.classList.remove('active');
        }
    });
}

function submitFeedback(event) {
    event.preventDefault();
    
    if (selectedRating === 0) {
        alert('Please select a rating');
        return;
    }
    
    const form = document.getElementById('feedbackForm');
    const successMessage = document.getElementById('successMessage');
    
    form.classList.add('hidden');
    successMessage.classList.remove('hidden');
    
    setTimeout(() => {
        form.classList.remove('hidden');
        successMessage.classList.add('hidden');
        form.reset();
        selectedRating = 0;
        document.querySelectorAll('.star-rating .star').forEach(star => {
            star.classList.remove('active');
        });
    }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Start globe animation
    generateAttack();
});
