import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('AI Chat History & Persistence System', () => {
  let dom;
  let document;
  let localStorageMock;

  // Mock states matching main.js implementation
  let chatSessions = {};
  let currentChatId = null;
  let conversationHistory = [];

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="ai-chat-history-list"></div>
          <div id="ai-messages"></div>
          <div id="ai-suggestions-container" style="display: block;">
            <div id="ai-suggestions"></div>
          </div>
        </body>
      </html>
    `);
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Reset mocks
    chatSessions = {};
    currentChatId = null;
    conversationHistory = [];

    // Mock localStorage
    localStorageMock = {
      data: {},
      getItem(key) {
        return this.data[key] || null;
      },
      setItem(key, value) {
        this.data[key] = value.toString();
      },
      removeItem(key) {
        delete this.data[key];
      },
      clear() {
        this.data = {};
      }
    };
    global.localStorage = localStorageMock;
  });

  // Mock implementations of main.js helper functions
  function loadChatSessions() {
    try {
      const saved = localStorage.getItem("cyberguard_ai_chats");
      if (saved) {
        chatSessions = JSON.parse(saved);
      } else {
        chatSessions = {};
      }
    } catch (e) {
      chatSessions = {};
    }
  }

  function saveChatSessions() {
    try {
      localStorage.setItem("cyberguard_ai_chats", JSON.stringify(chatSessions));
    } catch (e) {}
  }

  function createNewChatSession(firstMsgText) {
    const chatId = "chat_" + Date.now();
    const titleText = firstMsgText.replace(/[\p{Emoji_Presentation}\p{Extended_Pictographic}\uFE0F\uFE0E]/gu, "").trim();
    const title = titleText.length > 25 ? titleText.slice(0, 25) + "..." : titleText || "New Chat";

    chatSessions[chatId] = {
      id: chatId,
      title: title,
      history: [],
      timestamp: Date.now()
    };

    currentChatId = chatId;
    conversationHistory = [];
    saveChatSessions();
    return chatId;
  }

  function deleteChatSession(chatId) {
    delete chatSessions[chatId];
    saveChatSessions();
    if (currentChatId === chatId) {
      currentChatId = null;
      conversationHistory = [];
    }
  }

  function loadChatSession(chatId) {
    const session = chatSessions[chatId];
    if (!session) return;

    currentChatId = chatId;
    conversationHistory = session.history || [];
  }

  it('should load empty sessions when localStorage is empty', () => {
    loadChatSessions();
    expect(chatSessions).toEqual({});
  });

  it('should create a new session named from the first message', () => {
    const text = 'What is Reverse DNS?';
    const chatId = createNewChatSession(text);

    expect(chatId).toContain('chat_');
    expect(currentChatId).toBe(chatId);
    expect(chatSessions[chatId]).toBeDefined();
    expect(chatSessions[chatId].title).toBe('What is Reverse DNS?');
    expect(chatSessions[chatId].history).toEqual([]);
    
    // Check localstorage serialization
    const stored = JSON.parse(localStorage.getItem('cyberguard_ai_chats'));
    expect(stored[chatId]).toBeDefined();
    expect(stored[chatId].title).toBe('What is Reverse DNS?');
  });

  it('should load messages and set state when loading a session', () => {
    // Setup initial sessions
    const session1 = {
      id: 'chat_1',
      title: 'Session 1',
      history: [{ role: 'user', content: 'hello' }, { role: 'assistant', content: 'hi' }],
      timestamp: 1000
    };
    chatSessions['chat_1'] = session1;
    saveChatSessions();

    // Act
    loadChatSession('chat_1');

    // Assert
    expect(currentChatId).toBe('chat_1');
    expect(conversationHistory).toEqual(session1.history);
  });

  it('should delete session and clear current context if active session deleted', () => {
    createNewChatSession('Hello World');
    const chatId = currentChatId;
    expect(chatSessions[chatId]).toBeDefined();

    deleteChatSession(chatId);

    expect(chatSessions[chatId]).toBeUndefined();
    expect(currentChatId).toBeNull();
    expect(conversationHistory).toEqual([]);
  });
});
