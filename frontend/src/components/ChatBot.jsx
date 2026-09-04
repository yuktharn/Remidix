import { useState, useRef, useEffect } from 'react';
import {
  MessageCircle, X, Send, Loader2, ChevronDown, Bot, User,
  Mic, MicOff, Zap, Shield, Wrench, UploadCloud, GitCompare, Cloud, Globe, Sparkles, Check,
} from 'lucide-react';

const API_URL = 'https://remidix-backend.onrender.com';

function ChatBot({ projectId, project, onTriggerAction }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      id: 1,
      text: `Hi! I'm SecureCode Security Copilot. I can help you analyze vulnerabilities, understand CWE & OWASP risks, explain fixes, guide GitHub branch & PR workflows, and orchestrate deployments for${project ? ` "${project.name}"` : ' your repositories'}. Ask me anything!`,
      sender: 'bot',
      actions: [
        { type: 'owasp', label: 'Explain OWASP Top 10' },
        { type: 'scan_info', label: 'What is SQL Injection?' },
        { type: 'deployment', label: 'How does deployment work?' },
      ],
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [minimized, setMinimized] = useState(false);

  // Voice Input (Speech-to-Text) States
  const [isListening, setIsListening] = useState(false);
  const [voiceStatus, setVoiceStatus] = useState(''); // 'Listening...', 'Transcribing...', 'Ready to send'
  const recognitionRef = useRef(null);

  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // Update initial greeting when active project changes
  useEffect(() => {
    if (project) {
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          text: `Now auditing project **${project.name}** (${project.platform || 'GitHub'}). You can ask about its vulnerabilities, line-by-line fixes, branch status, or deployment readiness.`,
          sender: 'bot',
          actions: [
            { type: 'project_status', label: `Summarize ${project.name}` },
            { type: 'scan', label: 'Start Scan' },
            { type: 'fix', label: 'Generate Fixes' },
          ],
          timestamp: new Date(),
        },
      ]);
    }
  }, [projectId]);

  // Setup Web Speech API recognition
  useEffect(() => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SpeechRecognition) {
      const recognition = new SpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = true;
      recognition.lang = 'en-US';

      recognition.onstart = () => {
        setIsListening(true);
        setVoiceStatus('Listening...');
      };

      recognition.onresult = (event) => {
        setVoiceStatus('Transcribing...');
        let currentTranscript = '';
        for (let i = event.resultIndex; i < event.results.length; i++) {
          currentTranscript += event.results[i][0].transcript;
        }
        if (currentTranscript) {
          setInput(currentTranscript);
        }
      };

      recognition.onerror = (event) => {
        console.warn('Speech recognition error:', event.error);
        setIsListening(false);
        setVoiceStatus(event.error === 'not-allowed' ? 'Mic permission denied' : 'Voice error');
        setTimeout(() => setVoiceStatus(''), 3000);
      };

      recognition.onend = () => {
        setIsListening(false);
        setVoiceStatus('Ready to send');
        setTimeout(() => setVoiceStatus(''), 2500);
      };

      recognitionRef.current = recognition;
    }

    return () => {
      if (recognitionRef.current) {
        recognitionRef.current.abort();
      }
    };
  }, []);

  function toggleVoiceInput() {
    if (!recognitionRef.current) {
      alert('Voice recognition is not supported in this browser. Please use Chrome, Edge, or a Web Speech-compatible browser.');
      return;
    }

    if (isListening) {
      recognitionRef.current.stop();
      setIsListening(false);
    } else {
      try {
        setVoiceStatus('Starting microphone...');
        recognitionRef.current.start();
      } catch (err) {
        console.error('Failed to start voice recognition:', err);
      }
    }
  }

  async function handleSendMessage(e, overrideText) {
    if (e) e.preventDefault();
    const textToSend = overrideText || input;
    if (!textToSend || !textToSend.trim() || loading) return;

    const userMessage = {
      id: Date.now(),
      text: textToSend.trim(),
      sender: 'user',
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/copilot/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(projectId ? { 'x-project-id': String(projectId) } : {}),
        },
        body: JSON.stringify({
          message: textToSend.trim(),
          projectId: projectId ? Number(projectId) : null,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      const botMessage = {
        id: Date.now() + 1,
        text: data.reply || "I analyzed your request, but could not produce a response.",
        sender: 'bot',
        actions: data.actions || [],
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, botMessage]);
    } catch (err) {
      const errorMessage = {
        id: Date.now() + 1,
        text: `Error connecting to Copilot: ${err.message}. Please verify the backend is running.`,
        sender: 'bot',
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  }

  function handleActionClick(action) {
    if (onTriggerAction) {
      onTriggerAction(action);
    }

    // Also send an automated query to Copilot for conversational tracking
    let queryText = '';
    if (action.type === 'scan') queryText = 'Scan this repository';
    else if (action.type === 'fix') queryText = 'How do I fix the detected vulnerabilities?';
    else if (action.type === 'push') queryText = 'How do I push these fixes to GitHub?';
    else if (action.type === 'pr') queryText = 'Create a pull request for the corrected code';
    else if (action.type === 'deploy_backend') queryText = 'What is the backend deployment procedure?';
    else if (action.type === 'deploy_frontend') queryText = 'How do I deploy the frontend?';
    else if (action.type === 'owasp') queryText = 'What are the OWASP Top 10 vulnerabilities?';
    else if (action.type === 'scan_info') queryText = 'What is SQL Injection and CWE-89?';
    else if (action.type === 'deployment') queryText = 'How does the SecureCode deployment workflow work?';
    else if (action.type === 'project_status') queryText = `What is the security status of ${project?.name || 'this project'}?`;
    else queryText = action.label;

    handleSendMessage(null, queryText);
  }

  const projectName = project?.name || '';

  // Render markdown text with basic formatting and code blocks
  function renderFormattedMessage(text) {
    if (!text) return null;

    // Split by code blocks ```
    const codeBlockParts = text.split(/(```[\s\S]*?```)/g);

    return codeBlockParts.map((part, pIdx) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const lines = part.slice(3, -3).trim().split('\n');
        const lang = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : '';
        const codeContent = lang ? lines.slice(1).join('\n') : lines.join('\n');

        return (
          <div key={pIdx} style={{ margin: '8px 0', borderRadius: '8px', overflow: 'hidden', background: '#0f0f1c', border: '1px solid rgba(124,110,232,0.2)' }}>
            {lang && (
              <div style={{ padding: '4px 10px', fontSize: '11px', background: 'rgba(124,110,232,0.15)', color: '#a78bfa', fontWeight: 600 }}>
                {lang}
              </div>
            )}
            <pre style={{ margin: 0, padding: '10px 12px', fontSize: '12px', fontFamily: 'monospace', color: '#e2e8f0', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
              {codeContent}
            </pre>
          </div>
        );
      }

      // Format bold, inline code, and linebreaks
      const lines = part.split('\n');
      return (
        <span key={pIdx}>
          {lines.map((line, lIdx) => {
            // Replace bold **text** and inline `code`
            const formattedLine = line
              .split(/(\*\*.*?\*\*|`.*?`)/g)
              .map((seg, sIdx) => {
                if (seg.startsWith('**') && seg.endsWith('**')) {
                  return <strong key={sIdx} style={{ color: '#fff' }}>{seg.slice(2, -2)}</strong>;
                }
                if (seg.startsWith('`') && seg.endsWith('`')) {
                  return (
                    <code key={sIdx} style={{ padding: '2px 5px', borderRadius: '4px', background: 'rgba(124,110,232,0.2)', color: '#c4b5fd', fontSize: '12px', fontFamily: 'monospace' }}>
                      {seg.slice(1, -1)}
                    </code>
                  );
                }
                return seg;
              });

            return (
              <span key={lIdx}>
                {formattedLine}
                {lIdx < lines.length - 1 && <br />}
              </span>
            );
          })}
        </span>
      );
    });
  }

  // Floating button (closed state)
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          width: '58px',
          height: '58px',
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%)',
          border: 'none',
          color: '#fff',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 8px 32px rgba(99, 102, 241, 0.5), 0 0 0 2px rgba(255, 255, 255, 0.1)',
          zIndex: 10001,
          transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
        onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.08) translateY(-2px)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1) translateY(0)'; }}
        title="Open SecureCode AI Copilot"
      >
        <Bot size={26} />
      </button>
    );
  }

  return (
    <>
      {/* Background Dim & Blur Overlay */}
      <div
        onClick={() => setOpen(false)}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(10, 10, 20, 0.65)',
          backdropFilter: 'blur(5px)',
          zIndex: 10000,
          transition: 'all 0.3s ease',
        }}
      />

      {/* Chat Panel */}
      <div
        style={{
          position: 'fixed',
          top: minimized ? 'auto' : '24px',
          bottom: '24px',
          right: '24px',
          width: minimized ? '340px' : '450px',
          height: minimized ? '52px' : 'calc(100vh - 48px)',
          maxHeight: minimized ? '52px' : '780px',
          background: '#121224',
          border: '1px solid rgba(139, 92, 246, 0.35)',
          borderRadius: '16px',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(255, 255, 255, 0.05)',
          zIndex: 10001,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          transition: 'all 0.28s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '12px 18px',
            background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
            color: '#fff',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            cursor: minimized ? 'pointer' : 'default',
            flexShrink: 0,
            borderBottom: '1px solid rgba(255,255,255,0.1)',
          }}
          onClick={() => minimized && setMinimized(false)}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Bot size={18} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, letterSpacing: '-0.2px' }}>Security Copilot</h3>
                <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '10px', background: 'rgba(74, 222, 128, 0.25)', color: '#4ade80', fontWeight: 600 }}>RAG Live</span>
              </div>
              <p style={{ margin: 0, fontSize: '11px', opacity: 0.85 }}>
                {projectName ? `Target: ${projectName}` : 'Platform Security Auditor'}
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              onClick={(e) => { e.stopPropagation(); setMinimized(!minimized); }}
              style={{ background: 'rgba(255,255,255,0.15)', border: 'none', color: '#fff', cursor: 'pointer', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center' }}
              title={minimized ? 'Expand' : 'Minimize'}
            >
              <ChevronDown size={15} style={{ transform: minimized ? 'rotate(-180deg)' : '', transition: 'transform 0.2s' }} />
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); setOpen(false); }}
              style={{ background: 'rgba(255,255,255,0.15)', border: 'none', color: '#fff', cursor: 'pointer', padding: '6px', borderRadius: '6px', display: 'flex', alignItems: 'center' }}
              title="Close"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {!minimized && (
          <>
            {/* Messages Area */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '14px',
                background: '#121224',
              }}
            >
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                    gap: '6px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                      gap: '8px',
                      maxWidth: '88%',
                    }}
                  >
                    {msg.sender === 'bot' && (
                      <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.2)', border: '1px solid rgba(139, 92, 246, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                        <Bot size={14} style={{ color: '#a78bfa' }} />
                      </div>
                    )}
                    <div
                      style={{
                        padding: '11px 15px',
                        borderRadius: msg.sender === 'user' ? '14px 14px 2px 14px' : '14px 14px 14px 2px',
                        background: msg.sender === 'user' ? 'linear-gradient(135deg, #6366f1, #8b5cf6)' : '#1e1e38',
                        border: msg.sender === 'user' ? 'none' : '1px solid rgba(255,255,255,0.06)',
                        color: msg.sender === 'user' ? '#fff' : '#e2e8f0',
                        fontSize: '13px',
                        lineHeight: '1.55',
                        wordBreak: 'break-word',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
                      }}
                    >
                      {renderFormattedMessage(msg.text)}
                    </div>
                    {msg.sender === 'user' && (
                      <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(99, 102, 241, 0.3)', border: '1px solid rgba(99, 102, 241, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                        <User size={14} style={{ color: '#c7d2fe' }} />
                      </div>
                    )}
                  </div>

                  {/* Interactive Action Buttons */}
                  {msg.actions && msg.actions.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginLeft: msg.sender === 'bot' ? '36px' : '0', marginTop: '2px' }}>
                      {msg.actions.map((act, aIdx) => (
                        <button
                          key={aIdx}
                          onClick={() => handleActionClick(act)}
                          style={{
                            padding: '5px 10px',
                            background: 'rgba(139, 92, 246, 0.15)',
                            border: '1px solid rgba(139, 92, 246, 0.35)',
                            borderRadius: '16px',
                            color: '#c4b5fd',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                            transition: 'all 0.15s ease',
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.background = 'rgba(139, 92, 246, 0.3)';
                            e.currentTarget.style.color = '#fff';
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.background = 'rgba(139, 92, 246, 0.15)';
                            e.currentTarget.style.color = '#c4b5fd';
                          }}
                        >
                          <Sparkles size={11} />
                          {act.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {loading && (
                <div style={{ display: 'flex', justifyContent: 'flex-start', gap: '8px', alignItems: 'center' }}>
                  <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <Bot size={14} style={{ color: '#a78bfa' }} />
                  </div>
                  <div style={{ padding: '10px 14px', borderRadius: '14px 14px 14px 2px', background: '#1e1e38', color: '#94a3b8', fontSize: '12px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} />
                    <span>Analyzing project context & generating security advice...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Voice Status Banner */}
            {voiceStatus && (
              <div
                style={{
                  padding: '6px 14px',
                  background: isListening ? 'rgba(239, 68, 68, 0.2)' : 'rgba(99, 102, 241, 0.2)',
                  borderTop: '1px solid rgba(255,255,255,0.05)',
                  fontSize: '11px',
                  color: isListening ? '#fca5a5' : '#c7d2fe',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                {isListening ? (
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444', animation: 'pulse 1s infinite' }} />
                ) : (
                  <Check size={12} />
                )}
                {voiceStatus}
              </div>
            )}

            {/* Input Form */}
            <form
              onSubmit={(e) => handleSendMessage(e)}
              style={{
                padding: '12px 14px',
                background: '#0d0d1a',
                borderTop: '1px solid rgba(255,255,255,0.08)',
                display: 'flex',
                gap: '8px',
                alignItems: 'center',
                flexShrink: 0,
              }}
            >
              <button
                type="button"
                onClick={toggleVoiceInput}
                style={{
                  padding: '9px',
                  background: isListening ? '#ef4444' : 'rgba(255,255,255,0.06)',
                  border: isListening ? 'none' : '1px solid rgba(255,255,255,0.12)',
                  borderRadius: '8px',
                  color: isListening ? '#fff' : '#94a3b8',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.2s',
                }}
                title={isListening ? 'Stop listening' : 'Speak to Copilot (Speech-to-Text)'}
              >
                {isListening ? <MicOff size={16} /> : <Mic size={16} />}
              </button>

              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={
                  isListening
                    ? 'Listening... speak now'
                    : projectName
                    ? `Ask about ${projectName} security...`
                    : 'Ask any security or SecureCode question...'
                }
                disabled={loading}
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  background: '#16162a',
                  border: isListening ? '1px solid #ef4444' : '1px solid rgba(139, 92, 246, 0.3)',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '13px',
                  outline: 'none',
                }}
                onFocus={(e) => { if (!isListening) e.target.style.borderColor = '#6366f1'; }}
                onBlur={(e) => { if (!isListening) e.target.style.borderColor = 'rgba(139, 92, 246, 0.3)'; }}
              />

              <button
                type="submit"
                disabled={loading || !input.trim()}
                style={{
                  padding: '9px 14px',
                  background: input.trim() && !loading ? 'linear-gradient(135deg, #6366f1, #8b5cf6)' : 'rgba(255,255,255,0.06)',
                  border: 'none',
                  color: '#fff',
                  borderRadius: '8px',
                  cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.2s',
                  opacity: input.trim() && !loading ? 1 : 0.4,
                }}
                title="Send Message"
              >
                <Send size={15} />
              </button>
            </form>
          </>
        )}

        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
          @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.15); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
          }
        `}</style>
      </div>
    </>
  );
}

export default ChatBot;

