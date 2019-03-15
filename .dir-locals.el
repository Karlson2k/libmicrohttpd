;; Per-directory local variables for GNU Emacs 23 and later.

((nil
  . ((fill-column . 78)
     (tab-width   .  4)
     (indent-tabs-mode . nil)
     (show-trailing-whitespace . t)
     (c-basic-offset . 2)
     (ispell-check-comments . exclusive)
     (ispell-local-dictionary . "american")
     (safe-local-variable-values
	  '((c-default-style . "gnu")
	    (sentence-end-double-space . f)
        (eval add-hook 'prog-mode-hook #'flyspell-prog-mode)
        (flyspell-issue-message-flag . f) ; avoid messages for every word
        )))))
